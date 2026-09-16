rule TTP_XOR_WriteProcessMemory_921a {
  strings:
    $key_921a = { c5 68 [2] f7 4a [2] f1 7f [2] df 7f [2] e0 63 }

  condition:
    any of them
}