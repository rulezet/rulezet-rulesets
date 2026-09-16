rule TTP_XOR_WriteProcessMemory_cb7f {
  strings:
    $key_cb7f = { 9c 0d [2] ae 2f [2] a8 1a [2] 86 1a [2] b9 06 }

  condition:
    any of them
}