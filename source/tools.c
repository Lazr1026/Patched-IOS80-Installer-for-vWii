#include <gccore.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <fat.h>
#include <sdcard/wiisd_io.h>
#include "tools.h"

void Reboot()
{
	if (*(u32*)0x80001800) exit(0);
	SYS_ResetSystem(SYS_RETURNTOMENU, 0, 0);
}

void waitforbuttonpress(u32 *out, u32 *outGC)
{
	u32 pressed = 0;
	u32 pressedGC = 0;

	while (true)
	{
		WPAD_ScanPads();
		pressed = WPAD_ButtonsDown(0) | WPAD_ButtonsDown(1) | WPAD_ButtonsDown(2) | WPAD_ButtonsDown(3);

		PAD_ScanPads();
		pressedGC = PAD_ButtonsDown(0) | PAD_ButtonsDown(1) | PAD_ButtonsDown(2) | PAD_ButtonsDown(3);

		if(pressed || pressedGC) 
		{
			if (pressedGC)
			{
				// Without waiting you can't select anything
				usleep (20000);
			}
			if (out) *out = pressed;
			if (outGC) *outGC = pressedGC;
			return;
		}
	}
}

s32 Init_SD()
{
	__io_wiisd.shutdown();
	if(!fatMountSimple("sd", &__io_wiisd))
	{
		printf("FAT error, press any button to exit...\n");
		return -1;
	}
	return 0;
}

void Close_SD()
{
	fatUnmount("sd");
	__io_wiisd.shutdown();
}

void printheadline()
{
	int rows, cols;
	CON_GetMetrics(&cols, &rows);

	printf("Patched IOS80 Installer for vWii\n(MOD of IOS236 Installer MOD v8 Special Wii U vWii Edition)");

	char buf[64];
	sprintf(buf, "IOS%u (Rev %u)\n", IOS_GetVersion(), IOS_GetRevision());
	printf("\x1B[%d;%dH", 0, cols-strlen(buf)-1);
	printf(buf);
}

void set_highlight(bool highlight)
{
	if (highlight)
	{
		printf("\x1b[%u;%um", 47, false);
		printf("\x1b[%u;%um", 30, false);
	} else
	{
		printf("\x1b[%u;%um", 37, false);
		printf("\x1b[%u;%um", 40, false);
	}
}

//void Con_ClearLine()
//{
//	s32 cols, rows;
//	u32 cnt;
//
//	printf("\r");
//	fflush(stdout);
//
//	/* Get console metrics */
//	CON_GetMetrics(&cols, &rows);
//
//	/* Erase line */
//	for (cnt = 1; cnt < cols; cnt++) {
//		printf(" ");
//		fflush(stdout);
//	}
//
//	printf("\r");
//	fflush(stdout);
//}

