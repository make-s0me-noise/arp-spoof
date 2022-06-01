#include <stdio.h>
#include <pthread.h>
#include <stdlib.h>
#include <unistd.h>


typedef struct tTREAD{                          //?⑥닔 ?몄옄???ㅼ뼱媛?援ъ“泥?
	int sum;
	int count;
} prams;
void *func(prams* pram)                         //1遺??2000源뚯? ?뷀븯???⑥닔
{

	while(pram->count <= 2000)                          
	{
		pram->sum += pram->count;
		pram -> count++;
	}
}
int main()
{
	pthread_t thread[2];
	int id;
	
	int status;
	prams pram;
	pram.count = 0;
	pram.sum = 0;
	
	
	
	id = pthread_create(&thread[0], NULL, (void*)func,&pram);  //thread ?앹꽦
	id = pthread_create(&thread[1], NULL,(void*)func,&pram);   //thread ?앹꽦
	

	pthread_join(thread[0], (void **)&status);
	pthread_join(thread[1], (void **)&status);
    printf("sum = %d\n",pram.sum);
	return 0;
}