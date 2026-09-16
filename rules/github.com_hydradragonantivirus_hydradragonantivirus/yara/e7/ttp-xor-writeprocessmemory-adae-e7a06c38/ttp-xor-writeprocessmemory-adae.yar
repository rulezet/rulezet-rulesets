rule TTP_XOR_WriteProcessMemory_adae {
  strings:
    $key_adae = { fa dc [2] c8 fe [2] ce cb [2] e0 cb [2] df d7 }

  condition:
    any of them
}