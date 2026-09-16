rule TTP_XOR_WriteProcessMemory_fcbc {
  strings:
    $key_fcbc = { ab ce [2] 99 ec [2] 9f d9 [2] b1 d9 [2] 8e c5 }

  condition:
    any of them
}