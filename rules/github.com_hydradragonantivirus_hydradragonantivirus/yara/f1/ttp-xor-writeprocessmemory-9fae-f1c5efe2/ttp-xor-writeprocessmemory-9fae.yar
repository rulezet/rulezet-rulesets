rule TTP_XOR_WriteProcessMemory_9fae {
  strings:
    $key_9fae = { c8 dc [2] fa fe [2] fc cb [2] d2 cb [2] ed d7 }

  condition:
    any of them
}