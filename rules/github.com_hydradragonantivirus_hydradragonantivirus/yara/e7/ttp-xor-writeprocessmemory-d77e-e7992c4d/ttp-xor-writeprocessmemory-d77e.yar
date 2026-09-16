rule TTP_XOR_WriteProcessMemory_d77e {
  strings:
    $key_d77e = { 80 0c [2] b2 2e [2] b4 1b [2] 9a 1b [2] a5 07 }

  condition:
    any of them
}