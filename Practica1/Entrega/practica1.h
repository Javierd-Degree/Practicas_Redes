/***************************************************************************
 Ej1.h
 Compila: gcc -Wall -o Ej1P1 Ej1.c Ej1.h -lpcap
 Autor: Javier Delgado del Cerro, Javier López Cano
 2018 EPS-UAM
***************************************************************************/
#ifndef EJ1_H
#define EJ1_H

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <string.h>
#include <netinet/in.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <signal.h>
#include <time.h>

#define ERROR 1
#define OK 0
#define INTERFACE "eth0"

#define ETH_FRAME_MAX 1514	// Tamano maximo trama ethernet


void handle(int nsignal);

void fa_nuevo_paquete(uint8_t *usuario, const struct pcap_pkthdr* cabecera, const uint8_t* paquete);

#endif /*EJ1_H*/

