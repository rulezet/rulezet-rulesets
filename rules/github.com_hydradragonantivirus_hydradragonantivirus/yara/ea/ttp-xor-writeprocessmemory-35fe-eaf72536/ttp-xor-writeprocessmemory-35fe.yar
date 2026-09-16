rule TTP_XOR_WriteProcessMemory_35fe {
  strings:
    $key_35fe = { 62 8c [2] 50 ae [2] 56 9b [2] 78 9b [2] 47 87 }

  condition:
    any of them
}