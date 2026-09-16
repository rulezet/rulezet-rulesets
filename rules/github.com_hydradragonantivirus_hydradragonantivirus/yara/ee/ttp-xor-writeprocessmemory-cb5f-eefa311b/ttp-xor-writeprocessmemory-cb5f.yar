rule TTP_XOR_WriteProcessMemory_cb5f {
  strings:
    $key_cb5f = { 9c 2d [2] ae 0f [2] a8 3a [2] 86 3a [2] b9 26 }

  condition:
    any of them
}