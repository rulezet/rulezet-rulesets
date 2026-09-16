rule TTP_XOR_QUAD_CurrentVersionRun_00f0 {
  strings:
    $key_00f0 = { 53 9f [2] 77 91 [2] 5c bd [2] 72 9f [2] 66 84 [2] 69 9e [2] 77 83 [2] 75 82 [2] 6e 84 [2] 72 83 [2] 6e ac }

  condition:
    any of them
}