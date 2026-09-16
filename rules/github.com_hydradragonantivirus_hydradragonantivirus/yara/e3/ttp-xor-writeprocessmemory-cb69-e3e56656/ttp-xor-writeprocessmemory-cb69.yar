rule TTP_XOR_WriteProcessMemory_cb69 {
  strings:
    $key_cb69 = { 9c 1b [2] ae 39 [2] a8 0c [2] 86 0c [2] b9 10 }

  condition:
    any of them
}