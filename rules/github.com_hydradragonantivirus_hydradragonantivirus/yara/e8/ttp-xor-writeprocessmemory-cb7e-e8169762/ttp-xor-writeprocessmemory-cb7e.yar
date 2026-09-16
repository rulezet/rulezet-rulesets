rule TTP_XOR_WriteProcessMemory_cb7e {
  strings:
    $key_cb7e = { 9c 0c [2] ae 2e [2] a8 1b [2] 86 1b [2] b9 07 }

  condition:
    any of them
}