rule TTP_XOR_WriteProcessMemory_abae {
  strings:
    $key_abae = { fc dc [2] ce fe [2] c8 cb [2] e6 cb [2] d9 d7 }

  condition:
    any of them
}