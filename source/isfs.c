/****************************************************************************
 * Copyright (C) 2013 FIX94
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 ****************************************************************************/
#include <stdio.h>
#include <string.h>
#include <ogcsys.h>
#include "IOSPatcher.h"
#include "isfs.h"
#include "rijndael.h"
#include "sha1.h"
#include "tools.h"
#include "memory/mem2.hpp"
#include "../build/cert_sys.h"

#define round_up(x,n)	(-(-(x) & -(n)))
#define TITLE_UPPER(x)		((u32)((x) >> 32))
#define TITLE_LOWER(x)		((u32)(x))
#define ALIGN(n, x)			(((x) + (n - 1)) & ~(n - 1))

typedef struct map_entry
{
	char filename[8];
	u8 sha1[20];
} ATTRIBUTE_PACKED map_entry_t;

extern void encrypt_IOS(IOS *ios);

static fstats stats ATTRIBUTE_ALIGN(32);
void *Nand_get_file(const char *nand_file, size_t *size)
{
	//printf("Getting %s...", nand_file);
	*size = 0;
	void *buf = NULL;
	s32 fd = ISFS_Open(nand_file, ISFS_OPEN_READ);
	if(fd >= 0)
	{
		memset(&stats, 0, sizeof(fstats));
		if(ISFS_GetFileStats(fd, &stats) >= 0)
		{
			buf = MEM2_memalign(32, stats.file_length);
			if(buf != NULL)
			{
				*size = stats.file_length;
				ISFS_Read(fd, (char*)buf, *size);
				//printf("Done! Size: %u\n", *size);
			}
		}
		ISFS_Close(fd);
	}
	if(*size > 0)
		DCFlushRange(buf, *size);
	return buf;
}

static void *Nand_get_from_content(u8 *hash, size_t *size, map_entry_t *cm, u32 elements)
{
	void *buf = NULL;
	char ISFS_Filename[32] ATTRIBUTE_ALIGN(32);
	if(cm == NULL || elements == 0)
		return buf;
	u32 i;
	for(i = 0; i < elements; i++)
	{
		if(memcmp(cm[i].sha1, hash, 20) == 0)
		{
			sprintf(ISFS_Filename, "/shared1/%.8s.app", cm[i].filename);
			buf = Nand_get_file(ISFS_Filename, size);
			break;
		}
	}
    return buf;
}

s32 Nand_Read_into_memory(IOS **ios, u32 iosnr, u32 revision)
{
	printf("Getting IOS from NAND\n");
	/* SHA1 */
	u8 hash[20];
	/* 10 million bufs */
	char NandFile[256] ATTRIBUTE_ALIGN(0x20);
	tmd *TMD = NULL;
	tmd_content *TMD_Content = NULL;
	void *tmp_buf = NULL;
	map_entry_t *cm = NULL;
	size_t content_map_size = 0;
	size_t content_map_items = 0;
	size_t content_size = 0;
	u32 count = 0;
	/* Finally lets begin */
	printf("Init IOS\n");
	s32 ret = Init_IOS(ios);
	if(ret < 0)
		goto error;
	(*ios)->crl = NULL;
	(*ios)->crl_size = 0;
	/* TMD */
	printf("Get TMD\n");
	sprintf(NandFile, "/title/00000001/%08x/content/title.tmd", iosnr);
	(*ios)->tmd = Nand_get_file(NandFile, &((*ios)->tmd_size));
	if((*ios)->tmd == NULL || (*ios)->tmd_size == 0)
	{
		printf("Failed to get TMD!\n");
		goto error;
	}
	TMD = (tmd*)SIGNATURE_PAYLOAD((*ios)->tmd);
	if(TITLE_UPPER(TMD->title_id) != 1 || TITLE_LOWER(TMD->title_id) != iosnr)
	{
		printf("Wrong IOS Version!\n");
		goto error;
	}
	if(TMD->title_version != revision)
	{
		printf("Not the searched IOS revision found!\n");
		goto error;
	}
	/* Tik */
	printf("Get Tik\n");
	sprintf(NandFile, "/ticket/00000001/%08x.tik", iosnr);
	(*ios)->ticket = Nand_get_file(NandFile, &((*ios)->ticket_size));
	if((*ios)->ticket == NULL || (*ios)->ticket_size == 0)
	{
		printf("Failed to get Tik!\n");
		goto error;
	}
	/* Cert */
	printf("Getting certs\n");
	sprintf(NandFile, "/sys/cert.sys");
	(*ios)->certs = Nand_get_file(NandFile, &((*ios)->certs_size));
	if((*ios)->certs == NULL || (*ios)->certs_size == 0)
	{
		printf("Failed to get Cert!\n");
		goto error;
	}
	/* Content.map */
	printf("Get content.map\n");
	sprintf(NandFile, "/shared1/content.map");
	cm = (map_entry_t*)Nand_get_file(NandFile, &content_map_size);
	if(cm == NULL || content_map_size == 0)
	{
		printf("Failed to get the NAND content.map!\n");
		goto error;
	}
	content_map_items = content_map_size/sizeof(map_entry_t);
	/* Tell the patcher what to do */
	printf("Set num contents\n");
	ret = set_content_count(*ios, TMD->num_contents);
	if(ret < 0)
	{
		printf("Failed to set content count!\n");
		goto error;
	}
	printf("Loading contents");
	TMD_Content = TMD_CONTENTS(TMD);
	for(count = 0; count < TMD->num_contents; count++) 
	{
		printf(".");
		sprintf(NandFile, "/title/00000001/%08x/content/%08x.app", iosnr, TMD_Content[count].cid);
		tmp_buf = Nand_get_file(NandFile, &content_size);
		if(tmp_buf == NULL) //try shared1
			tmp_buf = Nand_get_from_content(TMD_Content[count].hash, &content_size, cm, content_map_items);
		if(tmp_buf == NULL)
		{
			printf("ERROR on getting content!\n");
			goto error;
		}
		if(content_size < TMD_Content[count].size)
		{
			printf("Content too small!\n");
			free(tmp_buf);
			goto error;
		}
		/* content checks and stuff */
		(*ios)->buffer_size[count] = round_up(ALIGN(16, (u32)TMD_Content[count].size), 64);
		(*ios)->decrypted_buffer[count] = MEM2_memalign(32, (*ios)->buffer_size[count]);
		if((*ios)->decrypted_buffer[count] == NULL)
		{
			printf("Couldn't allocate decrypt buffer!\n");
			goto error;
		}
		memset((*ios)->decrypted_buffer[count], 0, (*ios)->buffer_size[count]); /* IMPORTANT buf is not 16b aligned */
		memcpy((*ios)->decrypted_buffer[count], tmp_buf, TMD_Content[count].size); /* Already decrypted */
		free(tmp_buf);
		tmp_buf = NULL;
		memset(&hash, 0, sizeof(hash));
		SHA1((*ios)->decrypted_buffer[count], TMD_Content[count].size, hash);
		if(memcmp(TMD_Content[count].hash, hash, sizeof(hash)))
		{
			printf("Content hash is wrong!\n");
			goto error;
		}
		/* Will be used as soon as its finished */
		(*ios)->encrypted_buffer[count] = MEM2_memalign(32, (*ios)->buffer_size[count]);
		if((*ios)->encrypted_buffer[count] == NULL)
		{
			printf("Couldn't allocate encrypt buffer!\n");
			goto error;
		}
	}
	goto finish;
error:
	free_IOS(ios);
finish:
	if(cm != NULL)
		free(cm);
	return ret;
}
