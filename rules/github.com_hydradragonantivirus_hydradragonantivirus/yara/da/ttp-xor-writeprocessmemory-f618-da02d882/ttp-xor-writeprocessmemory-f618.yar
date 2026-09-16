rule TTP_XOR_WriteProcessMemory_f618 {
  strings:
    $key_f618 = { a1 6a [2] 93 48 [2] 95 7d [2] bb 7d [2] 84 61 }

  condition:
    any of them
}