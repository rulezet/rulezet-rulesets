rule TTP_XOR_WriteProcessMemory_cb18 {
  strings:
    $key_cb18 = { 9c 6a [2] ae 48 [2] a8 7d [2] 86 7d [2] b9 61 }

  condition:
    any of them
}