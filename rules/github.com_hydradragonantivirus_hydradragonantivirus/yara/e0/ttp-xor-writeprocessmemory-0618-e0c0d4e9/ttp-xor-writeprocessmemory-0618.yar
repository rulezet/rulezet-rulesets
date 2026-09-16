rule TTP_XOR_WriteProcessMemory_0618 {
  strings:
    $key_0618 = { 51 6a [2] 63 48 [2] 65 7d [2] 4b 7d [2] 74 61 }

  condition:
    any of them
}