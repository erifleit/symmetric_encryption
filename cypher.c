#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

void xor(int *inA, int *inB, int *out, int size);
void expand(int *in, int *out);
void split(int *in, int *outA, int*outB, int size);
void sbox(int *in, int* out, int box);
int compare(int *m1, int *m2);
void fun(int *input, int *key, int *output);
void light_DES(int *input, int *key, int *output);
void join(int *left, int *right, int*output, int size);
void key_rotator(int *masterkey, int *roundkey, int round_num);
void my_encrypt(int* master_key, int *iv,int *in, int *out, int r);
void decrypt(int *master_key, int *iv,int *in, int *out, int r);
void create_IV(int *master_key, int *iv);
void incrementIV(int *out);
void int_copy(int *input, int *output, int length);
void flipLR(int *input, int *output, int length);

/*
   By:
      Eric Fleith

   to compile:

      gcc cypher.c -o my-cypher

   To run it use the command line

   ./my−cipher [ECB/CTR/CBC] [enc/dec] [rounds] [key] [plaintext (binary)] [IV - (if decrypting only)]

   *if decrypting, you need to use the same IV as the one that was randomly generated during encryption.
   *CTR is able to handle any number of bits greater than 12.
   *key must be 9 digits long
   *only input binary numbers

*/

int main(int argc, char *argv[]){
   int i,j,k,mode,operation;
   char *key_in = argv[4]; // stores key input
   int *m_key = calloc(9,sizeof(int)); // variable for master-key
   int *r_key = calloc(8,sizeof(int)); // variable for round-key
   int rounds = atoi(argv[3]); // stores the number of rounds to use
   char *text_input = argv[5]; // gets the input as char
   int inlen = strlen(text_input); // gets length
   int *plain = calloc(inlen,sizeof(int)); //variable for plain text input
   int *cipher = calloc(inlen,sizeof(int)); //variable for cipher
   int *temp = calloc(inlen,sizeof(int));
   int *sub_plain = calloc(12,sizeof(int));
   int *sub_cipher = calloc(12,sizeof(int));
   int *sub_temp = calloc(12,sizeof(int));
   int *iv = calloc(12,sizeof(int));
   int *iv_copy = calloc(12,sizeof(int));

   //defines values for each functionality
   if(strcmp(argv[2],"enc")==0)operation = 1;
   if(strcmp(argv[2],"dec")==0)operation = 2;

   if(strcmp(argv[1],"ECB")==0)mode = 1;
   if(strcmp(argv[1],"CTR")==0)mode = 2;
   if(strcmp(argv[1],"CBC")==0)mode = 3;

   //exits if key is improper size
   if(strlen(key_in)!=9){
      printf("\n\nWrong key input.\n\n");
      exit(0);
   }
   for(i=0;i<9;i++)
      m_key[i] = (int)key_in[i]-48; //parses char variables to int

   int last_length = inlen%12; //checks the length of the last 12-bit block
   int pad_size = 0; // obtains the size of the padding that will be needed
   int needs_padding = 0; // value defines whether there will be padding
   if(last_length>0){ //if length is greater than zero
      pad_size = 12 - last_length; // obtain size of padding
      printf("\nThe length of the last block is %d",last_length); // tells the user how much padding will be used
      needs_padding = 1; // defines the need for padding
   }
   int numOfBlks = (inlen+pad_size)/12; //finds number of 12 bit blocks
   printf("\nThe number of blocks is %d\n",numOfBlks);

   if(operation==1 && mode!=1){ // if encrypting and not ECB
      create_IV(m_key,iv); //generate pseudo random iv
      int_copy(iv,iv_copy,12); //make copy of iv
   }
   if(operation==2 && mode != 1){ //if decrypting
      char *iv_input = argv[6]; //use iv from program arguments
      for(i=0;i<12;i++){
         iv[i] = (int)iv_input[i]-48;
      }
      int_copy(iv,iv_copy,12); //make copy of iv
   }
   if(mode==1){ //if using ECB mode
      for(i=0;i<12;i++){
         iv[i] = 0; //make iv a sequence of zeros, ECB doesn't use iv
      }
   }

   for(i=0;i<inlen;i++)
      plain[i] = (int)text_input[i]-48;//parse the inputs to int

   for(i=0;i<numOfBlks;i++){ //loops once for each 12 bit block
      if(operation==1){ // if encrypting
         if(i==numOfBlks-1 && needs_padding==1 && mode == 2){
            //if in the last step of encrypting while CTR
            //perform required opeations:
            for(j=0;j<last_length;j++){
               sub_temp[j]=plain[(i*12)+j];
               cipher[(i*12)+j]=sub_cipher[j];
            }
            for(j=last_length;j<12;j++)
               sub_temp[j]=sub_cipher[j];
            my_encrypt(m_key,iv,sub_temp,sub_cipher,rounds);
            for(k=0;k<12;k++){
               cipher[((i-1)*12)+k]=sub_cipher[k];
            }
         }
         else{ //if not in last step or not using CTR:
            for(j=0;j<12;j++)
               sub_temp[j]=plain[(i*12)+j];
            my_encrypt(m_key,iv,sub_temp,sub_cipher,rounds);
            for(k=0;k<12;k++){
               cipher[(i*12)+k]=sub_cipher[k];
               if(mode==3)iv[k]=sub_cipher[k]; //only if mode == CBC
            }
            if(mode==2)incrementIV(iv); // only if mode == CTR
         }
      }
      if(operation==2){ //if decrypting
         if(i==numOfBlks-2 && needs_padding==1 && mode == 2){
            //if last 2 steps of CTR decryption and needs padding

            int *iv2 = calloc(12,sizeof(int));
            int_copy(iv,iv2,12); //make copy of iv
            incrementIV(iv2); // iv2 is 1 greater than iv

            for(j=0;j<12;j++)
               sub_temp[j]=plain[(i*12)+j];
            decrypt(m_key,iv2,sub_temp,sub_cipher,rounds);
            for(k=0;k<last_length;k++){
               cipher[(i+1)*12+k]=sub_cipher[k];
               sub_temp[k]=plain[(i+1)*12+k];
            }
            for(k=last_length;k<12;k++)
               sub_temp[k]=sub_cipher[k];
            decrypt(m_key,iv,sub_temp,sub_cipher,rounds);
            for(k=0;k<12;k++){
               cipher[i*12+k]=sub_cipher[k];
            }
            break;
         }
         //if not last 2 steps, or doesn't need padding, or isn't CTR
         if(i<numOfBlks-2 || needs_padding == 0 || mode == 1 || mode == 3){
            for(j=0;j<12;j++)
               sub_temp[j]=plain[(i*12)+j];
            decrypt(m_key,iv,sub_temp,sub_cipher,rounds);
            for(k=0;k<12;k++){
               cipher[i*12+k]=sub_cipher[k];
               if(mode==3)iv[k] = sub_temp[k]; // only if mode == CBC
            }
            if(mode==2)incrementIV(iv); //only if mode == CTR
         }
      }
   }

   printf("\nInput is:  ");

   for(i=0;i<inlen;i++){
      if(i%12 == 0 && i!=0)printf(" ");
      printf("%d",plain[i]);
   }

   printf("\nOutput is: ");

   for(i=0;i<inlen;i++){
      if(i%12 == 0 && i!=0)printf(" ");
      printf("%d",cipher[i]);
   }

   printf("\niv was:    ");

   for(i=0;i<12;i++){
      if(i%12 == 0 && i!=0)printf(" ");
      printf("%d",iv_copy[i]);
   }

   printf("\n\n");
   return 0;
}

void create_IV(int *master_key, int *iv){

   int *fakeKey = calloc(9,sizeof(int)); //check if this needs to be 12
   int *myrandoms = calloc (12,sizeof(int));
   int *myrandoms2 = calloc (12,sizeof(int));
   int i = 0;
   int temp;
   time_t t;
   int *fakeiv = calloc(12,sizeof(int));
   for(i=0;i<3;i++){
      fakeKey[i] = master_key[i+6];
      fakeKey[i+3] = master_key[i+3];
      fakeKey[i+6] = master_key[i];
   }
   for(i=0;i<6;i++){
      fakeiv[i] = master_key[8-i];
      fakeiv[i+6] = master_key[i];
   }
   srand((unsigned) time(&t));
   for(i=0;i<12;i++){
      myrandoms[i] = fakeiv[rand()%12];
      usleep(50*1000);
   }
   my_encrypt(fakeKey, fakeiv, myrandoms, myrandoms2, (rand()%10)+1);
   flipLR(fakeiv,myrandoms,12);
   usleep(50*1000);
   decrypt(fakeKey, fakeiv, myrandoms2, iv, (rand()%10)+1);

   printf("\n");
}

void my_encrypt(int* master_key, int *iv, int *in, int *out, int r){
   int i,j;
   int *r_key = calloc(8,sizeof(int));
   int *xored = calloc(12,sizeof(int));
   xor(iv,in,xored,12);
   for(i=1;i<=r;i++){
      key_rotator(master_key, r_key, i);
      light_DES(xored,r_key,out);
      int_copy(out,xored,12);
   }
}
void decrypt(int* master_key, int *iv,int *in, int *out, int r){
   int i;
   int *r_key = calloc(8,sizeof(int));
   int *cipherIn = calloc(12,sizeof(int));
   int *local_out = calloc(12,sizeof(int));

   flipLR(in,cipherIn,12);

   for(i=r;i>0;i--){ //start with nth-key descending to first key
      key_rotator(master_key, r_key, i);
      light_DES(cipherIn,r_key,local_out);
      int_copy(local_out,cipherIn,12);
   }

   flipLR(cipherIn,local_out,12);

   // xor the iv after decryption
   xor(local_out,iv,out,12);
}
// rotates key
void key_rotator(int *masterkey, int *roundkey, int round_num){
   int r = (round_num % 9)-1;
   int i;
   for(i = 0 ; i < 8 ; i++){
      if(i+r < 9){
         roundkey[i] = masterkey[i+r];
      }
      if(i+r >= 9){
         roundkey[i] = masterkey[i+r-9];
      }
   }
}
// diagram in figure 1
void light_DES(int *input, int *key, int *output){
   int i;
   int outA[6];
   int outB[6];
   split(input, outA, outB, 12);
   int outB_2[6];
   fun(outB, key, outB_2);
   int xor_out[6];
   xor(outB_2, outA, xor_out, 6);
   join(outB, xor_out, output, 12);
}
// figure 2
void fun(int *input, int *key, int *output){

   int *local_o = calloc(8,sizeof(int));
   expand(input,local_o);
   int *xor_out = calloc(8,sizeof(int));
   xor(local_o, key, xor_out, 8);
   int *local_A = calloc(4,sizeof(int));
   int *local_B = calloc(4,sizeof(int));
   split(xor_out, local_A, local_B, 8);
   int *local_outA = calloc(3,sizeof(int));
   int *local_outB = calloc(3,sizeof(int));
   sbox(local_A, local_outA, 1);
   sbox(local_B, local_outB, 2);
   join(local_outA, local_outB, output,6);
}

void join(int *left, int *right, int*output, int size){
   int i = 0;
   for(i=0;i<size;i++){
      if(i<size/2)output[i]=left[i];
      else output[i]=right[i-(size/2)];
   }
}

void split(int *in, int *outA, int*outB, int size){
   int i = 0;
   for(i = 0;i<size/2;i++){
      outA[i]=in[i];
   }
   for(;i<size;i++){
      outB[i-(size/2)]=in[i];
   }
}
// Figure 3
void expand(int *in, int *out){
   out[0] = in [0];
   out[1] = in [1];
   out[2] = in [3];
   out[3] = in [2];
   out[4] = in [3];
   out[5] = in [2];
   out[6] = in [4];
   out[7] = in [5];
}

void xor(int *inA, int *inB, int *out, int size){
   int i = 0;
   while(i<size){
      if(inA[i] == inB[i]) out[i] = 0;
      else out[i] = 1;
      i++;
   }
}
// diagram in Figure 4
void sbox(int* in, int* out, int box){
   int value0[] = {0,0,0,0};
   int value1[] = {0,0,0,1};
   int value2[] = {0,0,1,0};
   int value3[] = {0,0,1,1};
   int value4[] = {0,1,0,0};
   int value5[] = {0,1,0,1};
   int value6[] = {0,1,1,0};
   int value7[] = {0,1,1,1};
   int value8[] = {1,0,0,0};
   int value9[] = {1,0,0,1};
   int valueA[] = {1,0,1,0};
   int valueB[] = {1,0,1,1};
   int valueC[] = {1,1,0,0};
   int valueD[] = {1,1,0,1};
   int valueE[] = {1,1,1,0};
   int valueF[] = {1,1,1,1};

   if(box == 1){
      if(compare(in,value7)==1 || compare(in,valueC)==1){
         out[0] = 0; out[1] = 0; out[2] = 0;
      }
      if(compare(in,value2)==1 || compare(in,value8)==1){
         out[0] = 0; out[1] = 0; out[2] = 1;
      }
      if(compare(in,value1)==1 || compare(in,valueB)==1){
         out[0] = 0; out[1] = 1; out[2] = 0;
      }
      if(compare(in,value4)==1 || compare(in,valueF)==1){
         out[0] = 0; out[1] = 1; out[2] = 1;
      }
      if(compare(in,value5)==1 || compare(in,value9)==1){
         out[0] = 1; out[1] = 0; out[2] = 0;
      }
      if(compare(in,value0)==1 || compare(in,valueE)==1){
         out[0] = 1; out[1] = 0; out[2] = 1;
      }
      if(compare(in,value3)==1 || compare(in,valueA)==1){
         out[0] = 1; out[1] = 1; out[2] = 0;
      }
      if(compare(in,value6)==1 || compare(in,valueD)==1){
         out[0] = 1; out[1] = 1; out[2] = 1;
      }
   }
   if(box == 2){
      if(compare(in,value1)==1 || compare(in,valueA)==1){
         out[0] = 0; out[1] = 0; out[2] = 0;
      }
      if(compare(in,value5)==1 || compare(in,valueE)==1){
         out[0] = 0; out[1] = 0; out[2] = 1;
      }
      if(compare(in,value7)==1 || compare(in,valueD)==1){
         out[0] = 0; out[1] = 1; out[2] = 0;
      }
      if(compare(in,value6)==1 || compare(in,value9)==1){
         out[0] = 0; out[1] = 1; out[2] = 1;
      }
      if(compare(in,value0)==1 || compare(in,valueF)==1){
         out[0] = 1; out[1] = 0; out[2] = 0;
      }
      if(compare(in,value3)==1 || compare(in,value8)==1){
         out[0] = 1; out[1] = 0; out[2] = 1;
      }
      if(compare(in,value2)==1 || compare(in,valueC)==1){
         out[0] = 1; out[1] = 1; out[2] = 0;
      }
      if(compare(in,value4)==1 || compare(in,valueD)==1){
         out[0] = 1; out[1] = 1; out[2] = 1;
      }
   }
   if(box != 1 && box != 2){
      printf("\n\nfix box number\n\n");
      exit(0);
   }
}
//increments a binary number by 1
void incrementIV(int *out){
   int i = 11;
   int j = 1;
   while(j == 1){
      if(out[i] == 0){
         out[i] = 1;
         i++;
         for(;i<12;i++){
            out[i] = 0;
         }
         break;
      }
      i--;
   }
}
//compares two arrays of integers
int compare(int *m1, int *m2){
   int num = 4;
   int index=0;
   while(index<num){
      if(m1[index] != m2[index]){
         return 0; // they're different
      }
      index++;
   }
   return 1;	//they're the same
}
//copies the content of an int array into another int array of the same size
void int_copy(int *input, int *output, int len){
   int i;
   for(i = 0; i < len; i++)
   {
       output[i] = input[i];
   }
}
//flips left and right
void flipLR(int *input, int *output, int length){
   int i;
   int *left = calloc(length/2,sizeof(int));
   int *right = calloc(length/2,sizeof(int));
   split(input,left,right,length);
   join(right,left,output,length);
}
