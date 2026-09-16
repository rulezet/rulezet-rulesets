rule TTP_XOR_WriteProcessMemory_b1fe {
  strings:
    $key_b1fe = { e6 8c [2] d4 ae [2] d2 9b [2] fc 9b [2] c3 87 }

  condition:
    any of them
}