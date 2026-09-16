rule TTP_XOR_WriteProcessMemory_8769 {
  strings:
    $key_8769 = { d0 1b [2] e2 39 [2] e4 0c [2] ca 0c [2] f5 10 }

  condition:
    any of them
}