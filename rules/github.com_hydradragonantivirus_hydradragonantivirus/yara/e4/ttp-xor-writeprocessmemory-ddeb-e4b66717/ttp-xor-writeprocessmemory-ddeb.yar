rule TTP_XOR_WriteProcessMemory_ddeb {
  strings:
    $key_ddeb = { 8a 99 [2] b8 bb [2] be 8e [2] 90 8e [2] af 92 }

  condition:
    any of them
}