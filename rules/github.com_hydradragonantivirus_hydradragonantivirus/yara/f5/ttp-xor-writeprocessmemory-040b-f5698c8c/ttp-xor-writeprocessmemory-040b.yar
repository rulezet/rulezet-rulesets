rule TTP_XOR_WriteProcessMemory_040b {
  strings:
    $key_040b = { 53 79 [2] 61 5b [2] 67 6e [2] 49 6e [2] 76 72 }

  condition:
    any of them
}