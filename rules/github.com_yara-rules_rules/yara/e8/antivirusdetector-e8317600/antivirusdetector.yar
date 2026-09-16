rule antivirusdetector
{

  meta:
    author = "Cylance"
    date = "2014-12-02"
    description = "http://cylance.com/opcleaver"

    strings:
        $s1 = "getShadyProcess"
        $s2 = "getSystemAntiviruses"
        $s3 = "AntiVirusDetector"

    condition:
        all of them
}