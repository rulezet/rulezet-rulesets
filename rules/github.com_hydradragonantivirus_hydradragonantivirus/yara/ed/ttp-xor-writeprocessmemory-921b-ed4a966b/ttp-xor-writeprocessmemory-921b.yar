rule TTP_XOR_WriteProcessMemory_921b {
  strings:
    $key_921b = { c5 69 [2] f7 4b [2] f1 7e [2] df 7e [2] e0 62 }

  condition:
    any of them
}