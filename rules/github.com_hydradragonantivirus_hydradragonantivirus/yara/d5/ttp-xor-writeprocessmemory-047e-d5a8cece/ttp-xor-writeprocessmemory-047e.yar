rule TTP_XOR_WriteProcessMemory_047e {
  strings:
    $key_047e = { 53 0c [2] 61 2e [2] 67 1b [2] 49 1b [2] 76 07 }

  condition:
    any of them
}