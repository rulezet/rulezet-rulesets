rule TTP_XOR_WriteProcessMemory_cb3e {
  strings:
    $key_cb3e = { 9c 4c [2] ae 6e [2] a8 5b [2] 86 5b [2] b9 47 }

  condition:
    any of them
}