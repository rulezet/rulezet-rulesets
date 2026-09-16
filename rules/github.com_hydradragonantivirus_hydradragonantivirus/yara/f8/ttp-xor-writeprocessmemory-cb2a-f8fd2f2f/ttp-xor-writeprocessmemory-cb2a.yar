rule TTP_XOR_WriteProcessMemory_cb2a {
  strings:
    $key_cb2a = { 9c 58 [2] ae 7a [2] a8 4f [2] 86 4f [2] b9 53 }

  condition:
    any of them
}