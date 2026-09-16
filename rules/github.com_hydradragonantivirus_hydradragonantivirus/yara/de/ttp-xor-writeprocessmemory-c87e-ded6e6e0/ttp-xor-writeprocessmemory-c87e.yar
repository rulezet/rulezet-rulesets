rule TTP_XOR_WriteProcessMemory_c87e {
  strings:
    $key_c87e = { 9f 0c [2] ad 2e [2] ab 1b [2] 85 1b [2] ba 07 }

  condition:
    any of them
}