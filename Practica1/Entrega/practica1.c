/***************************************************************************
 Ej1.c
 Compila: gcc -Wall -o Ej1P1 Ej1.c Ej1.h -lpcap
 Autor: Javier Delgado del Cerro, Javier López Cano
 2018 EPS-UAM
***************************************************************************/

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "practica1.h"


pcap_t *descr = NULL,*descr2 = NULL;
pcap_dumper_t *pdumper = NULL;
int contador = 0, numDigitos = 0;

void handle(int nsignal){
	printf("Control C pulsado\n");
  printf("Hemos leído %d paquetes.\n", contador);
	if(descr)
		pcap_close(descr);
	if(descr2)
		pcap_close(descr2);
	if(pdumper)
		pcap_dump_close(pdumper);
	exit(OK);
 }

void fa_nuevo_paquete(uint8_t *usuario, const struct pcap_pkthdr* cabecera, const uint8_t* paquete){
	int* num_paquete=(int *)usuario;
  int i;
	(*num_paquete)++;

  struct timeval ntime;
  ntime.tv_sec = cabecera->ts.tv_sec + 1800;
  ntime.tv_usec = cabecera->ts.tv_usec;
  struct pcap_pkthdr ccabecera;
  ccabecera.caplen = cabecera->caplen;
  ccabecera.len = cabecera->len;
  ccabecera.ts = ntime;

	printf("Nuevo paquete capturado a las %s",ctime((const time_t*)&(ccabecera.ts.tv_sec)));
  printf("Los %d primeros bytes del paquete son:\n", numDigitos);
  for(i = 0; i < numDigitos; i++){
    printf("%02X ", paquete[i]);
  }
  printf("\n\n");

	if(pdumper){
		pcap_dump((uint8_t *)pdumper, &ccabecera, paquete);
	}
}

int main(int argc, char **argv)
{
	int retorno=0;
	char errbuf[PCAP_ERRBUF_SIZE];
	char file_name[256];
	struct timeval time;


  if(argc == 1){
    printf("Número de argumentos incorrecto:\n\t-Ejecuta con un único argumento, el número de paquetes a capturar, si quieres capturar de interfaz.\n\t-Ejecuta con dos argumentos, el número de paquetes y al archivo de una traza, para analizar dicha traza pcap.\n");
    exit(ERROR);
  }else if (argc == 2){
    //Apertura de interface
    if ((descr = pcap_open_live(INTERFACE, ETH_FRAME_MAX, 0, 100, errbuf)) == NULL){
      printf("Error: pcap_open_live(): %s, %s %d.\n",errbuf,__FILE__,__LINE__);
      exit(ERROR);
    }
  }else{
    strcpy(file_name, argv[2]);

    //Apertura de interface
    if ((descr = pcap_open_offline(file_name, errbuf)) == NULL){
      printf("Error: pcap_open_offline(): %s, %s %d.\n",errbuf,__FILE__,__LINE__);
      exit(ERROR);
    }
  }

  numDigitos = atoi(argv[1]);

	if(signal(SIGINT,handle)==SIG_ERR){
		printf("Error: Fallo al capturar la senal SIGINT.\n");
		exit(ERROR);
	}

		//Para volcado de traza
	descr2=pcap_open_dead(DLT_EN10MB, ETH_FRAME_MAX);
	if (!descr2){
		printf("Error al abrir el dump.\n");
		pcap_close(descr);
		exit(ERROR);
	}
	gettimeofday(&time, NULL);
	sprintf(file_name,"captura.eth0.%lld.pcap",(long long)time.tv_sec);
	pdumper=pcap_dump_open(descr2,file_name);
	if(!pdumper){
		printf("Error al abrir el dumper: %s, %s %d.\n",pcap_geterr(descr2),__FILE__,__LINE__);
		pcap_close(descr);
		pcap_close(descr2);
		exit(ERROR);
	}

	//Se pasa el contador como argumento, pero sera mas comodo y mucho mas habitual usar variables globales
	retorno = pcap_loop (descr, -1, fa_nuevo_paquete, (uint8_t*)&contador);
	if(retorno == -1){ 		//En caso de error
		printf("Error al capturar un paquete %s, %s %d.\n",pcap_geterr(descr),__FILE__,__LINE__);
		pcap_close(descr);
		pcap_close(descr2);
		pcap_dump_close(pdumper);
		exit(ERROR);
	}
	else if(retorno==-2){ //pcap_breakloop() no asegura la no llamada a la funcion de atencion para paquetes ya en el buffer
		printf("Llamada a %s %s %d.\n","pcap_breakloop()",__FILE__,__LINE__);
	}
	else if(retorno == 0){
		printf("No mas paquetes o limite superado %s %d.\n",__FILE__,__LINE__);
	}

	pcap_dump_close(pdumper);
	pcap_close(descr);
	pcap_close(descr2);

	return OK;
}
