rule TTP_XOR_WriteProcessMemory_cb5a {
  strings:
    $key_cb5a = { 9c 28 [2] ae 0a [2] a8 3f [2] 86 3f [2] b9 23 }

  condition:
    any of them
}