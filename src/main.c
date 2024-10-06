#include <event2/event.h>
#include <pcap.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "lib/ndpi_common.h"

struct pcap_thread_args
{
    struct nDPI_workflow *workflow;
    struct event_base *base;
};

void pcap_event_handler(evutil_socket_t fd, short event, void *arg)
{
    struct nDPI_workflow *workflow = (struct nDPI_workflow *)arg;
    int ret = pcap_dispatch(workflow->pcap_handle, -1, ndpi_process_packet,
                            (unsigned char *)workflow);
    if (ret < 0)
    {
        fprintf(stderr, "Error in pcap_dispatch\n");
    }
}

void *pcap_thread_handler(void *arg)
{
    struct pcap_thread_args *args = (struct pcap_thread_args *)arg;

    int pcap_fd = pcap_get_selectable_fd(args->workflow->pcap_handle);
    if (pcap_fd == -1)
    {
        fprintf(stderr, "Unable to get selectable fd for pcap\n");
        event_base_free(args->base);  // Free event_base on failure
        return NULL;
    }

    struct event *pcap_event =
        event_new(args->base, pcap_fd, EV_READ | EV_PERSIST, pcap_event_handler,
                  args->workflow);

    if (!pcap_event)
    {
        fprintf(stderr, "Error creating event for pcap\n");
        event_base_free(args->base);  // Free event_base on failure
        return NULL;
    }

    event_add(pcap_event, NULL);
    event_base_dispatch(
        args->base);  // This will block until event loop finishes

    event_free(pcap_event);       // Free event after it's done
    event_base_free(args->base);  // Free event_base after dispatch loop ends
    return NULL;
}

int start_pcap_capture(const char *dev_name)
{
    struct event_base *base = event_base_new();
    if (!base)
    {
        fprintf(stderr, "Could not create event base\n");
        return -1;
    }

    struct nDPI_workflow *workflow = init_workflow(dev_name);
    if (!workflow)
    {
        fprintf(stderr, "Failed to initialize workflow for device %s\n",
                dev_name);
        event_base_free(base);  // Free event_base on failure
        return -1;
    }

    struct pcap_thread_args *args = malloc(sizeof(struct pcap_thread_args));
    if (!args)
    {
        fprintf(stderr, "Failed to allocate memory for thread arguments\n");
        event_base_free(base);
        pcap_close(workflow->pcap_handle);
        return -1;
    }

    args->base = base;
    args->workflow = workflow;

    pthread_t pcap_thread_id;
    if (pthread_create(&pcap_thread_id, NULL, pcap_thread_handler, args) != 0)
    {
        fprintf(stderr, "Error creating pcap thread for device %s\n", dev_name);
        free(args);  // Free args if thread creation fails
        event_base_free(base);
        pcap_close(workflow->pcap_handle);
        return -1;
    }

    pthread_detach(pcap_thread_id);  // Detach thread so it can clean up itself
    return 0;
}

int main(int argc, char *argv[])
{
    if (argc < 2)
    {
        fprintf(stderr, "Usage: %s <interface1> [interface2] ...\n", argv[0]);
        return EXIT_FAILURE;
    }

    for (int i = 1; i < argc; i++)
    {
        if (start_pcap_capture(argv[i]))
        {
            fprintf(stderr, "Failed to start packet capture on %s\n", argv[i]);
            return EXIT_FAILURE;
        }
    }

    // This loop should wait for threads to finish, using `sleep` for now
    while (1)
    {
        sleep(1);
    }

    return EXIT_SUCCESS;
}
