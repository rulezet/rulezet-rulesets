rule TTP_XOR_WriteProcessMemory_74fe {
  strings:
    $key_74fe = { 23 8c [2] 11 ae [2] 17 9b [2] 39 9b [2] 06 87 }

  condition:
    any of them
}