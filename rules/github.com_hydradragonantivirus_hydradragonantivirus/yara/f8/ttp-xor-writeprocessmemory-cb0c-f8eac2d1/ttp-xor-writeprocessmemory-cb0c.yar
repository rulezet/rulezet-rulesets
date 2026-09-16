rule TTP_XOR_WriteProcessMemory_cb0c {
  strings:
    $key_cb0c = { 9c 7e [2] ae 5c [2] a8 69 [2] 86 69 [2] b9 75 }

  condition:
    any of them
}