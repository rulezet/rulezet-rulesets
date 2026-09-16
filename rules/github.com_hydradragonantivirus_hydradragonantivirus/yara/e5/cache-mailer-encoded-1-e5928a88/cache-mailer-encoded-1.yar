rule cache_mailer_encoded_1 {
  meta:
    author = "Brian Laskowski"
    info   = " obfuscated php shell "

  strings:
    $s1 = "pod_h1kgzu0cqr"

  condition:
    all of them
}