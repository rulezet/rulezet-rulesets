rule TTP_XOR_WriteProcessMemory_cb43 {
  strings:
    $key_cb43 = { 9c 31 [2] ae 13 [2] a8 26 [2] 86 26 [2] b9 3a }

  condition:
    any of them
}