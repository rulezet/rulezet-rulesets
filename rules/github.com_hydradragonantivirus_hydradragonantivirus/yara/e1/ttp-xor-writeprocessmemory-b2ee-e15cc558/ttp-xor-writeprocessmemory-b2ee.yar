rule TTP_XOR_WriteProcessMemory_b2ee {
  strings:
    $key_b2ee = { e5 9c [2] d7 be [2] d1 8b [2] ff 8b [2] c0 97 }

  condition:
    any of them
}