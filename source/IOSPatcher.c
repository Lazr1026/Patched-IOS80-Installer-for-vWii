#include <gccore.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <malloc.h>
#include <network.h>

#include "IOSPatcher.h"
#include "rijndael.h"
#include "sha1.h"
#include "tools.h"
#include "http.h"
#include "isfs.h"
#include "memory/mem2.hpp"
#include "../build/cert_sys.h"

#define round_up(x,n)	(-(-(x) & -(n)))
#define TITLE_UPPER(x)		( (u32)((x) >> 32) )
#define TITLE_LOWER(x)		((u32)(x))

u8 commonkey[16] = { 0xeb, 0xe4, 0x2a, 0x22, 0x5e, 0x85, 0x93, 0xe4, 0x48, 0xd9, 0xc5, 0x45, 0x73, 0x81, 0xaa, 0xf7 };

s32 Wad_Read_into_memory(char *filename, IOS **ios, u32 iosnr, u32 revision);

void get_title_key(signed_blob *s_tik, u8 *key) 
{
	static u8 iv[16] ATTRIBUTE_ALIGN(0x20);
	static u8 keyin[16] ATTRIBUTE_ALIGN(0x20);
	static u8 keyout[16] ATTRIBUTE_ALIGN(0x20);

	const tik *p_tik;
	p_tik = (tik*)SIGNATURE_PAYLOAD(s_tik);
	u8 *enc_key = (u8 *)&p_tik->cipher_title_key;
	memcpy(keyin, enc_key, sizeof keyin);
	memset(keyout, 0, sizeof keyout);
	memset(iv, 0, sizeof iv);
	memcpy(iv, &p_tik->titleid, sizeof p_tik->titleid);
 
	aes_set_key(commonkey);
	aes_decrypt(iv, keyin, keyout, sizeof keyin);

	memcpy(key, keyout, sizeof keyout);
}

void change_ticket_title_id(signed_blob *s_tik, u32 titleid1, u32 titleid2) 
{
	static u8 iv[16] ATTRIBUTE_ALIGN(0x20);
	static u8 keyin[16] ATTRIBUTE_ALIGN(0x20);
	static u8 keyout[16] ATTRIBUTE_ALIGN(0x20);

	tik *p_tik;
	p_tik = (tik*)SIGNATURE_PAYLOAD(s_tik);
	u8 *enc_key = (u8 *)&p_tik->cipher_title_key;
	memcpy(keyin, enc_key, sizeof keyin);
	memset(keyout, 0, sizeof keyout);
	memset(iv, 0, sizeof iv);
	memcpy(iv, &p_tik->titleid, sizeof p_tik->titleid);

	aes_set_key(commonkey);
	aes_decrypt(iv, keyin, keyout, sizeof keyin);
	p_tik->titleid = (u64)titleid1 << 32 | (u64)titleid2;
	memset(iv, 0, sizeof iv);
	memcpy(iv, &p_tik->titleid, sizeof p_tik->titleid);
	
	aes_encrypt(iv, keyout, keyin, sizeof keyout);
	memcpy(enc_key, keyin, sizeof keyin);
}

void change_tmd_title_id(signed_blob *s_tmd, u32 titleid1, u32 titleid2) 
{
	tmd *p_tmd;
	u64 title_id = titleid1;
	title_id <<= 32;
	title_id |= titleid2;
	p_tmd = (tmd*)SIGNATURE_PAYLOAD(s_tmd);
	p_tmd->title_id = title_id;
}

void zero_sig(signed_blob *sig) 
{
	u8 *sig_ptr = (u8 *)sig;
	memset(sig_ptr + 4, 0, SIGNATURE_SIZE(sig)-4);
}

s32 brute_tmd(tmd *p_tmd) 
{
	u16 fill;
	for(fill=0; fill<65535; fill++) 
	{
		p_tmd->fill3=fill;
		sha1 hash;
		SHA1((u8 *)p_tmd, TMD_SIZE(p_tmd), hash);;
		  
		if (hash[0]==0) 
		{
			return 0;
		}
	}
	return -1;
}

s32 brute_tik(tik *p_tik) 
{
	u16 fill;
	for(fill=0; fill<65535; fill++) 
	{
		p_tik->padding=fill;
		sha1 hash;
		SHA1((u8 *)p_tik, sizeof(tik), hash);

		if (hash[0]==0)
		{
			return 0;
		}
	}
	return -1;
}
    
void forge_tmd(signed_blob *s_tmd) 
{
	zero_sig(s_tmd);
	brute_tmd(SIGNATURE_PAYLOAD(s_tmd));
}

void forge_tik(signed_blob *s_tik) 
{
	zero_sig(s_tik);
	brute_tik(SIGNATURE_PAYLOAD(s_tik));
}

int patch_version_check(u8 *buf, u32 size)
{
	u32 match_count = 0;
	u8 version_check[] = { 0xD2, 0x01, 0x4E, 0x56 };
	u32 i;
	
	for(i = 0; i < size - 4; i++)
	{
		if(!memcmp(buf + i, version_check, sizeof version_check))
		{
			buf[i] = 0xE0;
			buf[i+3] = 0;
			i += 4;
			match_count++;
			continue;
		}
	}
	return match_count;
}

int patch_hash_check(u8 *buf, u32 size) 
{
	u32 i;
	u32 match_count = 0;
	u8 new_hash_check[] = {0x20,0x07,0x4B,0x0B};
	u8 old_hash_check[] = {0x20,0x07,0x23,0xA2};
  
	for (i=0; i<size-4; i++) 
	{
		if (!memcmp(buf + i, new_hash_check, sizeof new_hash_check)) 
		{
			buf[i+1] = 0;
			i += 4;
			match_count++;
			continue;
		}

		if (!memcmp(buf + i, old_hash_check, sizeof old_hash_check)) 
		{
			buf[i+1] = 0;
			i += 4;
			match_count++;
			continue;
		}
	}
	return match_count;
}

int patch_identify_check(u8 *buf, u32 size)
{
	u32 match_count = 0;
	u8 identify_check[] = { 0x28, 0x03, 0xD1, 0x23 };
	u32 i;
	
	for(i = 0; i < size - 4; i++)
	{
		if(!memcmp(buf + i, identify_check, sizeof identify_check))
		{
			buf[i+2] = 0;
			buf[i+3] = 0;
			i += 4;
			match_count++;
			continue;
		}
	}
	return match_count;
}

int patch_patch_fsperms(u8 *buf, u32 size) 
{
	u32 i;
	u32 match_count = 0;
	u8 old_table[] = {0x42, 0x8B, 0xD0, 0x01, 0x25, 0x66};
	u8 new_table[] = {0x42, 0x8B, 0xE0, 0x01, 0x25, 0x66};
  
	for (i=0; i<size-sizeof old_table; i++) 
	{
		if (!memcmp(buf + i, old_table, sizeof old_table)) 
		{
			memcpy(buf + i, new_table, sizeof new_table);
			i += sizeof new_table;
			match_count++;
			continue;
		}
		
	}
	return match_count;
}

int patch_Kill_AntiSysTitleInstall(u8 *buf, u32 size)
{
	u32 i;
	u32 match_count = 0;
	u8 Kill_AntiSysTitleInstallv3_pt1[] = { 0x68, 0x1A, 0x2A, 0x01, 0xD0, 0x05 };
	u8 Kill_AntiSysTitleInstallv3_pt2[] = { 0xD0, 0x02, 0x33, 0x06, 0x42, 0x9A, 0xD1, 0x01 };
	u8 Kill_AntiSysTitleInstallv3_pt3[] = { 0x68, 0xFB, 0x2B, 0x00, 0xDB, 0x01 };
	
	for(i = 0; i < size - 6; i++)
	{
		if(!memcmp(buf + i, Kill_AntiSysTitleInstallv3_pt1, sizeof Kill_AntiSysTitleInstallv3_pt1))
		{
			buf[i+4] = 0x46;
			buf[i+5] = 0xC0;
			i += 6;
			match_count++;
			continue;
		}
	}
	
	for(i = 0; i < size - 8; i++)
	{
		if (!memcmp(buf + i, Kill_AntiSysTitleInstallv3_pt2, sizeof Kill_AntiSysTitleInstallv3_pt2)) 
		{
			buf[i] = 0x46;
			buf[i+1] = 0xC0;
			buf[i+6] = 0xE0;
			i += 8;
			match_count++;
			continue;
		}
	}
	
	for(i = 0; i < size - 6; i++)
	{
		if (!memcmp(buf + i, Kill_AntiSysTitleInstallv3_pt3, sizeof Kill_AntiSysTitleInstallv3_pt3)) 
		{
			buf[i+5] = 0x10;
			i += 6;
			match_count++;
			continue;
		}
	}
	return match_count;
}

void display_tag(u8 *buf) 
{
	printf("Firmware version: %s      Builder: %s\n", buf, buf+0x30);
}

void display_ios_tags(u8 *buf, u32 size) 
{
	u32 i;
	char *ios_version_tag = "$IOSVersion:";

	if (size == 64) 
	{
		display_tag(buf);
		return;
	}

	for (i=0; i<(size-64); i++) 
	{
		if (!strncmp((char *)buf+i, ios_version_tag, 10)) 
		{
			char version_buf[128], *date;
			while (buf[i+strlen(ios_version_tag)] == ' ') i++; // skip spaces
			strlcpy(version_buf, (char *)buf + i + strlen(ios_version_tag), sizeof version_buf);
			date = version_buf;
			strsep(&date, "$");
			date = version_buf;
			strsep(&date, ":");
			printf("%s (%s)\n", version_buf, date);
			i += 64;
		}
	}
}

bool contains_module(u8 *buf, u32 size, char *module) 
{
	u32 i;
	char *ios_version_tag = "$IOSVersion:";

	for (i=0; i<(size-64); i++) 
	{
		if (!strncmp((char *)buf+i, ios_version_tag, 10)) 
		{
			char version_buf[128];
			while (buf[i+strlen(ios_version_tag)] == ' ') i++; // skip spaces
			strlcpy(version_buf, (char *)buf + i + strlen(ios_version_tag), sizeof version_buf);
			i += 64;
			if (strncmp(version_buf, module, strlen(module)) == 0)
			{
				return true;
			}
		}
	}
	return false;
}

s32 module_index(IOS *ios, char *module)
{
	int i;
	for (i = 0; i < ios->content_count; i++)
	{
		if (!ios->decrypted_buffer[i] || !ios->buffer_size[i])
		{
			return -1;
		}
		
		if (contains_module(ios->decrypted_buffer[i], ios->buffer_size[i], module))
		{
			return i;
		}
	}
	return -1;
}

void decrypt_buffer(u16 index, u8 *source, u8 *dest, u32 len) 
{
	static u8 iv[16];
	memset(iv, 0, 16);
	memcpy(iv, &index, 2);
	aes_decrypt(iv, source, dest, len);
}

void encrypt_buffer(u16 index, u8 *source, u8 *dest, u32 len) 
{
	static u8 iv[16];
	memset(iv, 0, 16);
	memcpy(iv, &index, 2);
	aes_encrypt(iv, source, dest, len);
}

void decrypt_IOS(IOS *ios)
{
	u8 key[16];
	get_title_key(ios->ticket, key);
	aes_set_key(key);
	
	int i;
	for (i = 0; i < ios->content_count; i++)
	{
		decrypt_buffer(i, ios->encrypted_buffer[i], ios->decrypted_buffer[i], ios->buffer_size[i]);
	}
}

void encrypt_IOS(IOS *ios)
{
	u8 key[16];
	get_title_key(ios->ticket, key);
	aes_set_key(key);
	
	int i;
	for (i = 0; i < ios->content_count; i++)
	{
		encrypt_buffer(i, ios->decrypted_buffer[i], ios->encrypted_buffer[i], ios->buffer_size[i]);
	}
}

void display_tags(IOS *ios)
{
	int i;
	for (i = 0; i < ios->content_count; i++)
	{
		printf("Content %2u:  ", i);

		display_ios_tags(ios->decrypted_buffer[i], ios->buffer_size[i]);
	}
}

s32 Init_IOS(IOS **ios)
{
	if (ios == NULL)
		return -1;
		
	*ios = MEM2_memalign(32, sizeof(IOS));
	if (*ios == NULL)
		return -1;
	
	(*ios)->content_count = 0;

	(*ios)->certs = NULL;
	(*ios)->certs_size = 0;
	(*ios)->ticket = NULL;
	(*ios)->ticket_size = 0;
	(*ios)->tmd = NULL;
	(*ios)->tmd_size = 0;
	(*ios)->crl = NULL;
	(*ios)->crl_size = 0;
	
	(*ios)->encrypted_buffer = NULL;
	(*ios)->decrypted_buffer = NULL;
	(*ios)->buffer_size = NULL;
	
	return 0;
}

void free_IOS(IOS **ios)
{
	if (ios && *ios)
	{
		if ((*ios)->certs) free((*ios)->certs);
		if ((*ios)->ticket) free((*ios)->ticket);
		if ((*ios)->tmd) free((*ios)->tmd);
		if ((*ios)->crl) free((*ios)->crl);
		
		int i;
		for (i = 0; i < (*ios)->content_count; i++)
		{
			if ((*ios)->encrypted_buffer && (*ios)->encrypted_buffer[i]) free((*ios)->encrypted_buffer[i]);
			if ((*ios)->decrypted_buffer && (*ios)->decrypted_buffer[i]) free((*ios)->decrypted_buffer[i]);
		}
		
		if ((*ios)->encrypted_buffer) free((*ios)->encrypted_buffer);
		if ((*ios)->decrypted_buffer) free((*ios)->decrypted_buffer);
		if ((*ios)->buffer_size) free((*ios)->buffer_size);
		free(*ios);
	}	
}

s32 set_content_count(IOS *ios, u32 count)
{
	int i;
	if (ios->content_count > 0)
	{
		for (i = 0; i < ios->content_count; i++)
		{
			if (ios->encrypted_buffer && ios->encrypted_buffer[i]) free(ios->encrypted_buffer[i]);
			if (ios->decrypted_buffer && ios->decrypted_buffer[i]) free(ios->decrypted_buffer[i]);
		}
		
		if (ios->encrypted_buffer) free(ios->encrypted_buffer);
		if (ios->decrypted_buffer) free(ios->decrypted_buffer);
		if (ios->buffer_size) free(ios->buffer_size);
	}
	
	ios->content_count = count;
	if (count > 0)
	{
		ios->encrypted_buffer = MEM2_memalign(32, 4*count);
		ios->decrypted_buffer = MEM2_memalign(32, 4*count);
		ios->buffer_size = MEM2_memalign(32, 4*count);
		
		for (i = 0; i < count; i++) 
		{
			if (ios->encrypted_buffer) ios->encrypted_buffer[i] = NULL;
			if (ios->decrypted_buffer) ios->decrypted_buffer[i] = NULL;
		}

		if (!ios->encrypted_buffer || !ios->decrypted_buffer || !ios->buffer_size)
		{
			return -1;
		}
	}
	return 0;
}

s32 install_IOS(IOS *ios, bool skipticket)
{
	int ret;
	int cfd;

	if (!skipticket)
	{
		((u8*)(ios->ticket))[0x1F1] = 0x00; /* -1029 fix */
		ret = ES_AddTicket(ios->ticket, ios->ticket_size, ios->certs, ios->certs_size, ios->crl, ios->crl_size);
		if (ret < 0)
		{
			printf("ES_AddTicket returned: %d\n", ret);
			ES_AddTitleCancel();
			return ret;
		}
	}
	printf(".");

	ret = ES_AddTitleStart(ios->tmd, ios->tmd_size, ios->certs, ios->certs_size, ios->crl, ios->crl_size);
	if (ret < 0)
	{
		printf("\nES_AddTitleStart returned: %d\n", ret);
		ES_AddTitleCancel();
		return ret;
	}
	printf(".");

	tmd *tmd_data  = (tmd *)SIGNATURE_PAYLOAD(ios->tmd);

	int i;
	for (i = 0; i < ios->content_count; i++)
	{
		tmd_content *content = &tmd_data->contents[i];

		cfd = ES_AddContentStart(tmd_data->title_id, content->cid);
		if (cfd < 0)
		{
			printf("\nES_AddContentStart for content #%u cid %u returned: %d\n", i, content->cid, cfd);
			ES_AddTitleCancel();
			return cfd;
		}
		
		ret = ES_AddContentData(cfd, ios->encrypted_buffer[i], ios->buffer_size[i]);
		if (ret < 0)
		{
			printf("\nES_AddContentData for content #%u cid %u returned: %d\n", i, content->cid, ret);
			ES_AddTitleCancel();
			return ret;
		}
		
		ret = ES_AddContentFinish(cfd);
		if (ret < 0)
		{
			printf("\nES_AddContentFinish for content #%u cid %u returned: %d\n", i, content->cid, ret);
			ES_AddTitleCancel();
			return ret;
		}
		printf(".");
	}
	
	ret = ES_AddTitleFinish();
	if (ret < 0)
	{
		printf("\nES_AddTitleFinish returned: %d\n", ret);
		ES_AddTitleCancel();
		return ret;
	}
	printf(".\n");
	
	return 0;
}


int get_nus_object(u32 titleid1, u32 titleid2, char *content, u8 **outbuf, u32 *outlen) 
{
	static char buf[128];
	int retval;
	u32 http_status;

	snprintf(buf, 128, "http://nus.cdn.shop.wii.com/ccs/download/%08x%08x/%s", titleid1, titleid2, content);
	
	retval = http_request(buf, 1 << 31);
	if (!retval) 
	{
		printf("Error making http request\n");
		return -1;
	}

	retval = http_get_result(&http_status, outbuf, outlen); 
	
	if (((int)*outbuf & 0xF0000000) == 0xF0000000) 
	{
		return (int) *outbuf;
	}
	return 0;
}


s32 GetCerts(signed_blob** Certs, u32* Length)
{
	if (cert_sys_size != 2560)
	{
		return -1;
	}
	*Certs = MEM2_memalign(32, 2560);
	if (*Certs == NULL)
	{
		printf("Out of memory\n");
		return -1;	
	}
	memcpy(*Certs, cert_sys, cert_sys_size);
	*Length = 2560;

	return 0;
}

bool network_initialized = false;

s32 Download_IOS(IOS **ios, u32 iosnr, u32 revision)
{
	s32 ret;

	ret = Init_IOS(ios);
	if (ret < 0)
	{
		printf("Out of memory\n");
		goto err;
	}

	tmd *tmd_data  = NULL;
	u32 cnt;
	//static bool network_initialized = false;
	char buf[32];
	
	if (!network_initialized)
	{
		printf("Initializing network...");
		while (1) 
		{
			ret = net_init ();
			if (ret < 0) 
			{
				//if (ret != -EAGAIN) 
				if (ret != -11) 
				{
					printf ("net_init failed: %d\n", ret);
					goto err;
				}
			}
			if (!ret) break;
			usleep(100000);
			printf(".");
		}
		printf("done\n");
		network_initialized = true;
	}

	printf("Loading certs...\n");
	ret = GetCerts(&((*ios)->certs), &((*ios)->certs_size));
	if (ret < 0)
	{
		printf ("Loading certs from nand failed, ret = %d\n", ret);
		goto err;	
	}

	if ((*ios)->certs == NULL || (*ios)->certs_size == 0)
	{
		printf("certs error\n");
		ret = -1;
		goto err;		
	}

	if (!IS_VALID_SIGNATURE((*ios)->certs))
	{
		printf("Error: Bad certs signature!\n");
		ret = -1;
		goto err;
	}
	
	printf("Loading TMD...\n");
	sprintf(buf, "tmd.%u", revision);
	u8 *tmd_buffer = NULL;
	ret = get_nus_object(1, iosnr, buf, &tmd_buffer, &((*ios)->tmd_size));
	if (ret < 0)
	{
		printf("Loading tmd failed, ret = %u\n", ret);
		goto err;	
	}

	if (tmd_buffer == NULL || (*ios)->tmd_size == 0)
	{
		printf("TMD error\n");
		ret = -1;
		goto err;		
	}
	
	(*ios)->tmd_size = SIGNED_TMD_SIZE((signed_blob *)tmd_buffer);
 	(*ios)->tmd = MEM2_memalign(32, (*ios)->tmd_size);
	if ((*ios)->tmd == NULL)
	{
		printf("Out of memory\n");
		ret = -1;
		goto err;		
	}
	memcpy((*ios)->tmd, tmd_buffer, (*ios)->tmd_size);
	free(tmd_buffer);
	
	if (!IS_VALID_SIGNATURE((*ios)->tmd))
	{
		printf("Error: Bad TMD signature!\n");
		ret = -1;
		goto err;
	}

	printf("Loading ticket...\n");
	u8 *ticket_buffer = NULL;
	ret = get_nus_object(1, iosnr, "cetk", &ticket_buffer, &((*ios)->ticket_size));
	if (ret < 0)
	{
		printf("Loading ticket failed, ret = %u\n", ret);
		goto err;	
	}

	if (ticket_buffer == NULL || (*ios)->ticket_size == 0)
	{
		printf("ticket error\n");
		ret = -1;
		goto err;		
	}

	(*ios)->ticket_size = SIGNED_TIK_SIZE((signed_blob *)ticket_buffer);
 	(*ios)->ticket = MEM2_memalign(32, (*ios)->ticket_size);
	if ((*ios)->ticket == NULL)
	{
		printf("Out of memory\n");
		ret = -1;
		goto err;		
	}
	memcpy((*ios)->ticket, ticket_buffer, (*ios)->ticket_size);
	free(ticket_buffer);
	
	if(!IS_VALID_SIGNATURE((*ios)->ticket))
	{
		printf("Error: Bad ticket signature!\n");
		ret = -1;
		goto err;
	}

	/* Get TMD info */
	tmd_data = (tmd *)SIGNATURE_PAYLOAD((*ios)->tmd);

	printf("Checking titleid and revision...\n");
	if (TITLE_UPPER(tmd_data->title_id) != 1 || TITLE_LOWER(tmd_data->title_id) != iosnr)
	{
		printf("IOS has titleid: %08x%08x but expected was: %08x%08x\n", TITLE_UPPER(tmd_data->title_id), TITLE_LOWER(tmd_data->title_id), 1, iosnr);
		ret = -1;
		goto err;
	}

	if (tmd_data->title_version != revision)
	{
		printf("IOS has revision: %u but expected was: %u\n", tmd_data->title_version, revision);
		ret = -1;
		goto err;
	}

	ret = set_content_count(*ios, tmd_data->num_contents);
	if (ret < 0)
	{
		printf("Out of memory\n");
		goto err;
	}

	printf("Loading contents");
	for (cnt = 0; cnt < tmd_data->num_contents; cnt++) 
	{
		printf(".");
		tmd_content *content = &tmd_data->contents[cnt];

		/* Encrypted content size */
		(*ios)->buffer_size[cnt] = round_up((u32)content->size, 64);

		sprintf(buf, "%08x", content->cid);
   
		ret = get_nus_object(1, iosnr, buf, &((*ios)->encrypted_buffer[cnt]), &((*ios)->buffer_size[cnt]));

		if ((*ios)->buffer_size[cnt] % 16) 
		{
			printf("Content %u size is not a multiple of 16\n", cnt);
			ret = -1;
			goto err;
		}

   		if ((*ios)->buffer_size[cnt] < (u32)content->size) 
		{
			printf("Content %u size is too small\n", cnt);
			ret = -1;
			goto err;
   		} 

		(*ios)->decrypted_buffer[cnt] = MEM2_memalign(32, (*ios)->buffer_size[cnt]);
		if (!(*ios)->decrypted_buffer[cnt])
		{
			printf("Out of memory\n");
			ret = -1;
			goto err;
		}

	}
	printf("done\n");
	
	printf("Reading file into memory complete.\n");

	printf("Decrypting IOS...\n");
	decrypt_IOS(*ios);

	tmd_content *p_cr = TMD_CONTENTS(tmd_data);
	sha1 hash;
	int i;

	printf("Checking hashes...\n");
	for (i=0;i < (*ios)->content_count;i++)
	{
		SHA1((*ios)->decrypted_buffer[i], (u32)p_cr[i].size, hash);
		if (memcmp(p_cr[i].hash, hash, sizeof hash) != 0)
		{
			printf("Wrong hash for content #%u\n", i);
			ret = -1;
			goto err;
		}
	}	

	goto out;

err:
	free_IOS(ios);

out:
	return ret;
}

s32 get_IOS(IOS **ios, u32 iosnr, u32 revision)
{
	char buf[64];
/*	u32 pressed;
	u32 pressedGC;
	int selection = 0;*/
	int ret;
	ret = Init_SD();
	if(ret >= 0)
	{
		sprintf(buf, "sd:/IOS%u-64-v%u.wad", iosnr, revision);
		ret = Wad_Read_into_memory(buf, ios, iosnr, revision);
		if(ret < 0)
		{
			sprintf(buf, "sd:/IOS%u-64-v%u.wad.out.wad", iosnr, revision);
			ret = Wad_Read_into_memory(buf, ios, iosnr, revision);
		}
		Close_SD();
	}
	if(ret < 0)
		ret = Nand_Read_into_memory(ios, iosnr, revision);
	return ret;
}

s32 install_unpatched_IOS(u32 iosversion, u32 revision, bool free)
{
	int ret;
	IOS *ios;
	
	printf("Getting IOS%u revision %u...\n", iosversion, revision);
	ret = get_IOS(&ios, iosversion, revision);
	if (ret < 0)
	{
		printf("Error reading IOS into memory\n");
		return ret;
	}
	
	printf("\n");
	
	printf("Installing IOS%u Rev %u...\n", iosversion, revision);
	ret = install_IOS(ios, false);
	if (ret < 0)
	{
		printf("Error: Could not install IOS%u Rev %u\n", iosversion, revision);
		free_IOS(&ios);
		return ret;
	}
	printf("done\n");

	if (free) free_IOS(&ios);
	return 0;
}

s32 Install_patched_IOS(u32 iosnr, u32 iosrevision, bool es_trucha_patch, bool es_identify_patch, bool nand_patch, bool version_patch, bool Kill_AntiSysTitleInstall_patch, u32 location, u32 newrevision, bool free)
{
	int ret;
	if (iosnr == location && iosrevision == newrevision && !es_trucha_patch && !es_identify_patch && !nand_patch && !Kill_AntiSysTitleInstall_patch)
	{
		ret = install_unpatched_IOS(iosnr, iosrevision, free);
		return ret;
	}
	
	IOS *ios;
	int index;
	bool tmd_dirty = false;
	bool tik_dirty = false;
	
	printf("Getting IOS%u revision %u...\n", iosnr, iosrevision);
	ret = get_IOS(&ios, iosnr, iosrevision);
	if (ret < 0)
	{
		printf("Error reading IOS into memory\n");
		return -1;
	}
	
	tmd *p_tmd = (tmd*)SIGNATURE_PAYLOAD(ios->tmd);
	tmd_content *p_cr = TMD_CONTENTS(p_tmd);

	if (es_trucha_patch || es_identify_patch || nand_patch || version_patch || Kill_AntiSysTitleInstall_patch)
	{
		index = module_index(ios, "ES:");
		if (index < 0)
		{
			printf("Could not identify ES module\n");
			free_IOS(&ios);
			return -1;
		}
		int trucha = 0;
		int identify = 0;
		int nand = 0;
		int version = 0;
		int systitle = 0;
		
		if (es_trucha_patch)
		{		
			printf("Patching trucha bug into ES module(#%u)...", index);
			trucha = patch_hash_check(ios->decrypted_buffer[index], ios->buffer_size[index]);
			printf("patched %u hash check(s)\n", trucha);
		}
		
		if (es_identify_patch)
		{
			printf("Patching ES_Identify in ES module(#%u)...", index);
			identify = patch_identify_check(ios->decrypted_buffer[index], ios->buffer_size[index]);
			printf("patch applied %u time(s)\n", identify);		
		}
		
		if (nand_patch)
		{
			printf("Patching nand permissions in ES module(#%u)...", index);
			nand = patch_patch_fsperms(ios->decrypted_buffer[index], ios->buffer_size[index]);
			printf("patch applied %u time(s)\n", nand);		
		}
		
		if (version_patch)
		{
			printf("Patching version check in ES module(#%u)...", index);
			version = patch_version_check(ios->decrypted_buffer[index], ios->buffer_size[index]);
			printf("patch applied %u time(s)\n", version);			
		}
		
		if (Kill_AntiSysTitleInstall_patch)
		{
			printf("Patching out Systitle Anti-Install Routine in ES module(#%u)...", index);
			systitle = patch_Kill_AntiSysTitleInstall(ios->decrypted_buffer[index], ios->buffer_size[index]);
			printf("patch applied %u time(s)\n", systitle);
		}
		
		if (trucha > 0 || identify > 0 || nand > 0 || version > 0 || systitle > 0)
		{
			// Force the patched module to be not shared
			tmd_content *content = &p_tmd->contents[index];
			content->type = 1;

			// Update the content hash inside the tmd
			sha1 hash;
			SHA1(ios->decrypted_buffer[index], (u32)p_cr[index].size, hash);
			memcpy(p_cr[index].hash, hash, sizeof hash);
			tmd_dirty = true;
		}
	}

	if (iosnr != location)
	{
		change_ticket_title_id(ios->ticket, 1, location);
		change_tmd_title_id(ios->tmd, 1, location);
		tmd_dirty = true;
		tik_dirty = true;
	}
	
	if (iosrevision != newrevision)
	{
		p_tmd->title_version = newrevision;
		tmd_dirty = true;
	}

	if (tmd_dirty)
	{
		printf("Trucha signing the tmd...\n");
		forge_tmd(ios->tmd);
	}

	if (tik_dirty)
	{
		printf("Trucha signing the ticket..\n");
		forge_tik(ios->ticket);
	}

	printf("Encrypting IOS...\n");
	encrypt_IOS(ios);
	
	printf("Preparations complete\n\n");
	

	printf("Installing...\n");
	ret = install_IOS(ios, false);
	if (ret < 0)
	{
		free_IOS(&ios);
		if (ret == -1017 || ret == -2011)
		{
			printf("You need to use an IOS with trucha bug.\n");
			printf("That's what the IOS15 downgrade is good for...\n");
		} else
		if (ret == -1035)
		{
			printf("Has your installed IOS%u a higher revison than %u?\n", iosnr, iosrevision);
		}
		
		return -1;
	}
	printf("done\n");
	
	if (free) free_IOS(&ios);
	return 0;
}


s32 Downgrade_TMD_Revision(void *ptmd, u32 tmd_size, void *certs, u32 certs_size) 
{
	// The revison of the tmd used as paramter here has to be >= the revision of the installed tmd
	s32 ret;

	printf("Setting the revision to 0...\n");

	ret = ES_AddTitleStart(ptmd, tmd_size, certs, certs_size, NULL, 0);
	if (ret < 0) 
	{
		if (ret == -1035)
		{
			printf("Error: ES_AddTitleStart returned %d, maybe you need an updated Downgrader\n", ret);
		} else
		{
			printf("Error: ES_AddTitleStart returned %d\n", ret);
		}
		ES_AddTitleCancel();
		return ret;
	}

	s32 file;
	char *tmd_path = "/tmp/title.tmd";
	
	ret = ISFS_Delete(tmd_path);	
	if (ret < 0) 
	{
		printf("Error: ISFS_Delete returned %d\n", ret);
		ES_AddTitleCancel();
		ISFS_Deinitialize();
		return ret;
	}
	ret = ISFS_CreateFile(tmd_path, 0, 3, 3, 3);
	if (ret < 0) 
	{
		printf("Error: ISFS_CreateFile returned %d\n", ret);
		ES_AddTitleCancel();
		ISFS_Deinitialize();
		return ret;
	}

	file = ISFS_Open(tmd_path, ISFS_OPEN_RW);
	if (file < 0)
	{
		printf("Error: ISFS_Open returned %d\n", file);
		ES_AddTitleCancel();
		ISFS_Deinitialize();
		return file;
	}
	
	u8 *tmd = (u8 *)ptmd;
	tmd[0x1dc] = 0;
	tmd[0x1dd] = 0;
	
	ret = ISFS_Write(file, (u8 *)ptmd, tmd_size);
	if (ret < 0) 
	{
		printf("Error: ISFS_Write returned %d\n", ret);
		ISFS_Close(file);
		ES_AddTitleCancel();
		ISFS_Deinitialize();
		return ret;
	}

	ISFS_Close(file);
	ISFS_Deinitialize();

	ret = ES_AddTitleFinish();
	if (ret < 0) 
	{
		printf("Error: ES_AddTitleFinish returned %d\n", ret);
		return ret;
	}
	
	return 1;
}

s32 Downgrade_IOS(u32 iosversion, u32 highrevision, u32 lowrevision, bool free)
{
	printf("Preparing downgrade of IOS%u from revison: %u to: %u\n", iosversion, highrevision, lowrevision);

	int ret;
	IOS *highios;
	IOS *lowios;
	
	printf("Getting IOS%u revision %u...\n", iosversion, highrevision);
	ret = get_IOS(&highios, iosversion, highrevision);
	if (ret < 0)
	{
		printf("Error reading IOS into memory\n");
		return ret;
	}
	
	printf("Getting IOS%u revision %u...\n", iosversion, lowrevision);
	ret = get_IOS(&lowios, iosversion, lowrevision);
	if (ret < 0)
	{
		printf("Error reading IOS into memory\n");
		free_IOS(&highios);
		return ret;
	}

	printf("\n");
	printf("Downgrading involves two steps:\n");
	printf("Step 1: Set the revison to 0\n");
	printf("Step 2: Install IOS with low revision\n");
	printf("Preparations complete, step 1...\n");

	u32 pressed;
	u32 pressedGC;	
	waitforbuttonpress(&pressed, &pressedGC);
	if (pressed != WPAD_BUTTON_A && pressedGC != PAD_BUTTON_A)
	{
		printf("Other button pressed\n");
		free_IOS(&highios);
		free_IOS(&lowios);
		return -1;
	}
	
	printf("Installing ticket...\n");
	ret = ES_AddTicket(highios->ticket, highios->ticket_size, highios->certs, highios->certs_size, highios->crl, highios->crl_size);
	if (ret < 0)
	{
		printf("ES_AddTicket returned: %d\n", ret);
		free_IOS(&highios);
		free_IOS(&lowios);
		ES_AddTitleCancel();
		return ret;
	}	

	ret = Downgrade_TMD_Revision(highios->tmd, highios->tmd_size, highios->certs, highios->certs_size);
	if (ret < 0)
	{
		printf("Error: Could not set the revision to 0\n");
		free_IOS(&highios);
		free_IOS(&lowios);
		return ret;
	}

	printf("Revision set to 0, step 1 of downgrade complete.\n");
	printf("\n");
	printf("step 2 of downgrade...\n");

	waitforbuttonpress(&pressed, &pressedGC);
	if (pressed != WPAD_BUTTON_A && pressedGC != PAD_BUTTON_A)
	{
		printf("Other button pressed\n");
		free_IOS(&highios);
		free_IOS(&lowios);
		return -1;
	}
	
	printf("Installing IOS%u Rev %u...\n", iosversion, lowrevision);
	ret = install_IOS(lowios, true);
	if (ret < 0)
	{
		printf("Error: Could not install IOS%u Rev %u\n", iosversion, lowrevision);
		free_IOS(&highios);
		free_IOS(&lowios);
		return ret;
	}

	printf("IOS%u downgrade to revision: %u complete.\n", iosversion, lowrevision);
	if (free) {
		free_IOS(&highios);
		free_IOS(&lowios);
	}

	return 0;
}

s32 GetTMD(u64 TicketID, signed_blob **Output, u32 *Length)
{
    signed_blob* TMD = NULL;

    u32 TMD_Length;
    s32 ret;

    /* Retrieve TMD length */
    ret = ES_GetStoredTMDSize(TicketID, &TMD_Length);
    if (ret < 0)
        return ret;

    /* Allocate memory */
    TMD = (signed_blob*)MEM2_memalign(32, (TMD_Length+31)&(~31));
    if (!TMD)
        return IPC_ENOMEM;

    /* Retrieve TMD */
    ret = ES_GetStoredTMD(TicketID, TMD, TMD_Length);
    if (ret < 0)
    {
        free(TMD);
        return ret;
    }

    /* Set values */
    *Output = TMD;
    *Length = TMD_Length;

    return 0;
}

s32 checkTitle(u64 title_id)
{
	signed_blob *TMD = NULL;
    tmd *t = NULL;
    u32 TMD_size = 0;
    s32 ret = 0;

    ret = GetTMD(title_id, &TMD, &TMD_size);
    
    if (ret == 0) {
		t = (tmd*)SIGNATURE_PAYLOAD(TMD);
        return t->title_version;
    } else {
		ret = -2;
	}
    free(TMD);
    return ret;
}

s32 checkIOS(u32 IOS)
{
    // Get tmd to determine the version of the IOS
    return checkTitle(((u64)(1) << 32) | (IOS));
}
