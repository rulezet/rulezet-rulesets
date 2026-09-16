rule TTP_XOR_WriteProcessMemory_cb0a {
  strings:
    $key_cb0a = { 9c 78 [2] ae 5a [2] a8 6f [2] 86 6f [2] b9 73 }

  condition:
    any of them
}