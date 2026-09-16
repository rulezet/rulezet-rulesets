rule TTP_XOR_WriteProcessMemory_cb28 {
  strings:
    $key_cb28 = { 9c 5a [2] ae 78 [2] a8 4d [2] 86 4d [2] b9 51 }

  condition:
    any of them
}