//
// Program: smashECB.php
// Author: Brian "Hermit" Mork
// Date: 2015-09-27
// Description: Takes in a formatted bit AES-ECB ciphertext and known plaintext
//              (both in 32 byte formatted hex lines) and then builds a lookup table
//              to deciper a third file (similarly formatted).  Built to defeat the
//              ~gwalton/homework/cryptography challenge for the DerbyCon 5 CTF
//              HINT: To generate a file from raw binary/text that is appropriate for
//              consumption use a hex dump, e.g.:
//              xxd -g 16 {FILENAME}
//              Reversing the clear can generate the same if you don't use the builtin
//              translation from the tool (e.g. if the target isn't text):
//              xxd -r -p {FILE} > {BINARY}

<?php

$stepLevel=32;

function buildLookupTable($pfile, $cfile, $blocks, $chunk, $showTable) {
  $plainFile = fopen($pfile, "r");
  $cipherFile = fopen($cfile, "r");
  $blocksize = $blocks;

  // Note that the below assumes the two files are linecount matched
  // with each line containing a single ECB block
  while (($plainLine = fgets($plainFile)) !== false ) {
    // Reset where we're looking to first position
    $poscounter = 0;

    // Pull in a line of ciphertext, which is positionally matched to plain
    $cipherLine = fgets($cipherFile);

    // Loop through the two lines to build matches
    while (($poscounter < $blocksize) !== false ) {
      $ctext = substr($cipherLine, $poscounter, $chunk);
      $ptext = substr($plainLine, $poscounter, $chunk);
      // As these are fixed position indicators there is the potential for overwrite
      $lookupTable[$poscounter][$ctext] = $ptext;
      $poscounter += $chunk;
    } 
  }

  // Housekeeping
  fclose($plainFile);
  fclose($cipherFile);
  // Print the table if requested
  if ($showTable) {
    print_r($lookupTable);
  }
  return $lookupTable;
}

// Main execution (pull arguments)
$argPlainFile = $argv[1];
$argCipherFile = $argv[2];
$argNewCipherFile = $argv[3];
$argBlocks = $argv[4];

$codebook = buildLookupTable($argPlainFile, $argCipherFile, $argBlocks, $stepLevel, false);

// Loop through the array and solve
$secretFile = fopen($argNewCipherFile, "r");
echo "Cleartext of " . $argCipherFile . ":\n";
while (($secretLine = fgets($secretFile)) !== false ) {
  $poscounter = 0;
  $translatedLine = "";
  while (($poscounter < $argBlocks) !== false ) {
    $secretByte = substr($secretLine, $poscounter, $stepLevel);
    if (in_array(array($poscounter, $secretByte), $codebook)) {
      $clearByte = $codebook[$poscounter][$secretByte];
    } else {
      $clearByte = $codebook[$poscounter][$secretByte]
    }
    // Next line left for debugging steps/blocks
    //echo "Lookup " . $secretByte . " at position " . $poscounter . ": ". $clearByte . "\n";
    $translatedLine .= $clearByte;
    $poscounter += $stepLevel;
  }
  $cleartext = rtrim(hex2bin($translatedLine));
  echo $cleartext . " "; 
}

?>
