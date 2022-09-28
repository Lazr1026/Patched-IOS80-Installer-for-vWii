#include <sys/unistd.h>
#include <wiiuse/wpad.h>

void Reboot();
void waitforbuttonpress(u32 *out, u32 *outGC);
void printheadline();
void set_highlight(bool highlight);
void Con_ClearLine();
s32 Init_SD();
s32 Init_USB();
void Close_SD();
void Close_USB();

