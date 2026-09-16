rule TTP_XOR_WriteProcessMemory_026e {
  strings:
    $key_026e = { 55 1c [2] 67 3e [2] 61 0b [2] 4f 0b [2] 70 17 }

  condition:
    any of them
}