rule TTP_XOR_WriteProcessMemory_14ee {
  strings:
    $key_14ee = { 43 9c [2] 71 be [2] 77 8b [2] 59 8b [2] 66 97 }

  condition:
    any of them
}