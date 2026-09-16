rule TTP_XOR_WriteProcessMemory_cb0d {
  strings:
    $key_cb0d = { 9c 7f [2] ae 5d [2] a8 68 [2] 86 68 [2] b9 74 }

  condition:
    any of them
}