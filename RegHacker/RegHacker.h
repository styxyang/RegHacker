#ifndef _REGHACKER_H_
#define _REGHACKER_H_

#ifndef CTL_CODE
	#pragma message("CTL_CODE undefined. Include winioctl.h or wdm.h")
#endif

#define IOCTL_SET_EVENT CTL_CODE(               \
    FILE_DEVICE_UNKNOWN,                        \
    0x800,                                      \
    METHOD_BUFFERED,                            \
    FILE_ANY_ACCESS)

#endif /* _REGHACKER_H_ */
