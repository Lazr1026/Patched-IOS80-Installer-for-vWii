#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gccore.h>
#include <malloc.h>

#include "IOSPatcher.h"
#include "identify.h"
#include "wad.h"
#include "tools.h"
#include "network.h"
//#include "uninstall.h"
#include "memory/mem2.hpp"

#define IOS80version 7200

void InitVideo()
{
	VIDEO_Init();
	GXRModeObj *rmode = VIDEO_GetPreferredMode(NULL);
	void *xfb = MEM_K0_TO_K1(SYS_AllocateFramebuffer(rmode));
	VIDEO_Configure(rmode);
	VIDEO_SetNextFramebuffer(xfb);
	VIDEO_SetBlack(FALSE);
	VIDEO_Flush();
	VIDEO_WaitVSync();
	if(rmode->viTVMode&VI_NON_INTERLACE)
		VIDEO_WaitVSync();
	CON_InitEx(rmode, 24, 32, rmode->fbWidth - (32), rmode->xfbHeight - (48));
	VIDEO_ClearFrameBuffer(rmode, xfb, COLOR_BLACK);
}

s32 __u8Cmp(const void *a, const void *b)
{
	return *(u8 *)a-*(u8 *)b;
}

void __AHBPROT_FatalError(void) {
		printf("\nFATAL ERROR:\n");
		printf("Unable to initialise the initial patches.\n");
		printf("This either means you didn't follow the download\n");
		printf("and launching instructions correctly, or your IOS\n");
		printf("is not vulnerable for an unknown reason.\n");
		printf("Perhaps you need to update the Homebrew Channel (HBC).\n");
		printf("Installation cannot continue.  Press any button to exit...\n");
		waitforbuttonpress(NULL, NULL);
		Reboot();
}
extern void __exception_setreload(int t);
int main(int argc, char* argv[])
{
	__exception_setreload(10);
	int ret;

	InitVideo();
	MEM_init();

	printheadline();
	printf("\n\nThanks, in no particular order, go to Wiipower, oggzee, Team Twiizers,\n");
	printf("tona, Joseph Jordan and anybody else who has code included in the app.\n");
	printf("The app was quite a simple job, built upon their actual real work.\n");
	printf("App made by Dr Clipper/Davebaol, then automated by ZRicky11.\n");
	printf("Wii U's vWii IOS support added by damysteryman.\n");
	printf("Usage of the internal NAND IOS80 added by FIX94.\n \n");
	printf("This Patched IOS80 installer is for Wii U's vWii ONLY!\nUsing this in a regular Wii will result in a broken IOS80, which will\ncause a brick if you have System menu 4.3 installed!\n");
	printf("REQUIRES either: vWii IOS80 v7200 wad located at SD:/IOS80-64-v7200.wad!\n(It is not avaible on NUS, must dump from a vWii or acquire elsewhere)\n...Or IOS80 v7200 already installed on vWii.\n\n");

	printf("WARNING! THIS APP MODIFIES SYSTEM MENU IOS ON vWii!\nThe patch itself may be very simple, but still quite a potential risk\nto install, due to no BootMii for vWii!\n");
	printf("PATCH IOS80 AT YOUR OWN RISK! If for some reason the install fails,\nvWii could brick! Again, CONTINUE AT YOUR OWN RISK!\n\n");
	/* Enable AHBPROT on title launch */
	Patch_AHB();
	ret = (__IOS_LoadStartupIOS() == 0 && *(vu32*)0xCD800064 == 0xFFFFFFFF);

	printf("Patching IOS\n");
	PatchIOS(true);
	usleep(1000);
	printf("Init ISFS\n");
	ISFS_Initialize();

	PAD_Init();
	WPAD_Init();
	WPAD_SetDataFormat(WPAD_CHAN_0, WPAD_FMT_BTNS_ACC_IR);

	/* Fatal error */
	if (!ret)
		__AHBPROT_FatalError();
	printf("Read the big warning above for 30 seconds before continuing...\n");
	sleep(30);
	printf("Press any button to continue...\n");
	waitforbuttonpress(NULL, NULL);

	printf("About to install IOS80\n");
	ret = Install_patched_IOS(80, IOS80version, true, false, false, false, false, 80, IOS80version, false);

	ISFS_Deinitialize();
	if (ret < 0) {
		printf("IOS80 Install failed!  Press any button to exit...\n");
		waitforbuttonpress(NULL, NULL);
		Reboot();
	}
	printf("\nIOS80 Installation is complete!\nPress any button to exit.");
	waitforbuttonpress(NULL, NULL);
	
	Reboot();

	return 0;
}