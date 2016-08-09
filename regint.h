typedef struct {
	ULONG RefCount;
	ULONG ExtFlags : 16;
	ULONG PrivateAlloc : 1;
	ULONG Delete : 1;
	ULONG HiveUnloaded : 1;
	ULONG Decommissioned : 1;
	ULONG LockTablePresent : 1;
	ULONG TotalLevels : 10;
	ULONG : 1;
	ULONG DelayedDeref : 1;
	ULONG DelayedClose : 1;
	ULONG Parking : 1;
} CM_KEY_CONTROL_BLOCK;

typedef struct {
	LIST_ENTRY 		HiveList;
	LIST_ENTRY 		PostList;
	CM_KEY_CONTROL_BLOCK 	*KeyControlBlock;
	struct CM_KEY_BODY 	*KeyBody;
	ULONG 			Filter : 30;
	ULONG 			WatchTree : 1;
	ULONG 			NotifyPending : 1;
	ULONG 			opaque[0];
} CM_NOTIFY_BLOCK;

typedef struct CM_KEY_BODY {
	ULONG 			Type;
	CM_KEY_CONTROL_BLOCK 	*KeyControlBlock;
	CM_NOTIFY_BLOCK 	*NotifyBlock;
	void 			*procid;
	LIST_ENTRY 		KeyBodyList;
} CM_KEY_BODY;

#define CM_KCB_READ_ONLY_KEY    0x0080
#define CM_KCB_NO_DELAY_CLOSE 	0x0020


