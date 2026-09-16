rule TTP_XOR_WriteProcessMemory_cb6f {
  strings:
    $key_cb6f = { 9c 1d [2] ae 3f [2] a8 0a [2] 86 0a [2] b9 16 }

  condition:
    any of them
}