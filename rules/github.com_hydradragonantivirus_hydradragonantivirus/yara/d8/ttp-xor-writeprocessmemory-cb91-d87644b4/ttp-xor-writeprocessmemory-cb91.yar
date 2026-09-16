rule TTP_XOR_WriteProcessMemory_cb91 {
  strings:
    $key_cb91 = { 9c e3 [2] ae c1 [2] a8 f4 [2] 86 f4 [2] b9 e8 }

  condition:
    any of them
}