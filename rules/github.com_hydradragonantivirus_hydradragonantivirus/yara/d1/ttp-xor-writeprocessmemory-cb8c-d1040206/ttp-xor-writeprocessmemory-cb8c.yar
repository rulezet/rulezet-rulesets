rule TTP_XOR_WriteProcessMemory_cb8c {
  strings:
    $key_cb8c = { 9c fe [2] ae dc [2] a8 e9 [2] 86 e9 [2] b9 f5 }

  condition:
    any of them
}