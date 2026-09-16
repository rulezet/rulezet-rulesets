rule TTP_XOR_WriteProcessMemory_999e {
  strings:
    $key_999e = { ce ec [2] fc ce [2] fa fb [2] d4 fb [2] eb e7 }

  condition:
    any of them
}