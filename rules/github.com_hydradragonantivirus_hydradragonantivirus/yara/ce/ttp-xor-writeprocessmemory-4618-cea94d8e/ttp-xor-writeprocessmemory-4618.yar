rule TTP_XOR_WriteProcessMemory_4618 {
  strings:
    $key_4618 = { 11 6a [2] 23 48 [2] 25 7d [2] 0b 7d [2] 34 61 }

  condition:
    any of them
}