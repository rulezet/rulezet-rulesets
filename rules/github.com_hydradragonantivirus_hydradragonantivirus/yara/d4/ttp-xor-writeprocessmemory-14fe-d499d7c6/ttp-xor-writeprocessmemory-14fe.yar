rule TTP_XOR_WriteProcessMemory_14fe {
  strings:
    $key_14fe = { 43 8c [2] 71 ae [2] 77 9b [2] 59 9b [2] 66 87 }

  condition:
    any of them
}