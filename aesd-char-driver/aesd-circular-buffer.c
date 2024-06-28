/**
 * @file aesd-circular-buffer.c
 * @brief Functions and data related to a circular buffer imlementation
 *
 * @author Dan Walkes
 * @date 2020-03-01
 * @copyright Copyright (c) 2020
 *
 */

#ifdef __KERNEL__
#include <linux/string.h>
#else
#include <string.h>
#endif

#include "aesd-circular-buffer.h"


/**
 * @param buffer the buffer to search for corresponding offset.  Any necessary locking must be performed by caller.
 * @param char_offset the position to search for in the buffer list, describing the zero referenced
 *      character index if all buffer strings were concatenated end to end
 * @param entry_offset_byte_rtn is a pointer specifying a location to store the byte of the returned aesd_buffer_entry
 *      buffptr member corresponding to char_offset.  This value is only set when a matching char_offset is found
 *      in aesd_buffer.
 * @return the struct aesd_buffer_entry structure representing the position described by char_offset, or
 * NULL if this position is not available in the buffer (not enough data is written).
 */
struct aesd_buffer_entry *aesd_circular_buffer_find_entry_offset_for_fpos(struct aesd_circular_buffer *buffer,
            size_t char_offset, size_t *entry_offset_byte_rtn )
{
    /**
    * TODO: implement per description
    */

    uint8_t n = 0;
    uint8_t curr;
    uint8_t i;

    if (buffer->full) 
    {
        n = AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED;
    } 
    else 
    {
        n = buffer->in_offs + AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED - buffer->out_offs;
        if (n >= AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED) 
        {
            n -= AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED;
        }
    }

    curr = buffer->out_offs;
    for (i=0; i < n; ++i) 
    {
        if (char_offset < buffer->entry[curr].size) 
        {
            *entry_offset_byte_rtn = char_offset;
            return &buffer->entry[curr];
        }

        char_offset -= buffer->entry[curr].size;
        curr++;
        if (curr >= AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED) 
        {
            curr = 0;
        }
    }
    return NULL;
}

/**
* Adds entry @param add_entry to @param buffer in the location specified in buffer->in_offs.
* If the buffer was already full, overwrites the oldest entry and advances buffer->out_offs to the
* new start location.
* Any necessary locking must be handled by the caller
* Any memory referenced in @param add_entry must be allocated by and/or must have a lifetime managed by the caller.
*/
const char *aesd_circular_buffer_add_entry(struct aesd_circular_buffer *buffer, const struct aesd_buffer_entry *add_entry)
{
    /**
    * TODO: implement per description
    */

    const char *removed = NULL;

    if (buffer->full) {
        removed = buffer->entry[buffer->in_offs].buffptr;
    }
    buffer->entry[buffer->in_offs] = *add_entry;
    buffer->in_offs++;
    if (buffer->in_offs >= AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED) {
        buffer->in_offs = 0;
    }
    if (buffer->full) {
        buffer->out_offs = buffer->in_offs;
    } else if (buffer->out_offs == buffer->in_offs) {
        buffer->full = true;
    }
    return removed; 
}

/**
* Initializes the circular buffer described by @param buffer to an empty struct
*/
void aesd_circular_buffer_init(struct aesd_circular_buffer *buffer)
{
    memset(buffer,0,sizeof(struct aesd_circular_buffer));
}

/** 
 * Function to grab the total size of the buffer for assignment 9
 */
size_t aesd_get_total_size(struct aesd_circular_buffer *buffer)
{
    size_t total_size = 0;
    uint8_t max = 0;
    uint8_t idx;
    uint8_t pos;

    if (buffer->full)
    {
        max = AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED;
    }
    else
    {
        max = buffer->in_offs + AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED - buffer->out_offs;
        if (max >= AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED)
        {
            max -= AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED;
        }
    }

    pos = buffer->out_offs;
    for (idx = 0; idx < max; ++idx)
    {
        total_size += buffer->entry[pos].size;
        pos++;
        if (pos >= AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED)
        {
            pos = 0;
        }
    }

    return total_size;
}

/** 
 * Function to grab the write command offset of the buffer for assignment 9
 */
long aesd_get_offset(struct aesd_circular_buffer *buffer, uint32_t write_cmd, uint32_t write_cmd_offset)
{
    size_t total_size = 0;
    uint8_t max = 0;
    uint8_t idx;
    uint8_t pos;

    if (buffer->full)
    {
        max = AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED;
    }
    else
    {
        max = buffer->in_offs + AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED - buffer->out_offs;
        if (max >= AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED)
        {
            max -= AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED;
        }
    }

    if (write_cmd >= max)
    {
        return -1;
    }

    pos = buffer->out_offs;
    for (idx = 0; idx < max; ++idx)
    {
        total_size += buffer->entry[pos].size;
        pos++;
        if (pos >= AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED)
        {
            pos = 0;
        }
    }

    if (write_cmd_offset >= buffer->entry[pos].size)
    {
        return -1;
    }

    total_size += write_cmd_offset;

    return total_size;

}
