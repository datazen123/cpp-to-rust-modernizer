/* Legacy sustainment-asset risk scoring - C, last touched ~2015 per commit
 * log on the old system (days-since-check / overdue / risk-tier logic with
 * a "fail" keyword bump), ported to Rust, the direction memory-safety
 * guidance worldwide (NSA/CISA, the White House ONCD, MISRA C's
 * safety-critical lineage - see README) points toward for this class of
 * bug.
 *
 * Reads records from stdin, one per line, pipe-delimited:
 *   id|last_checked_days_ago|check_interval_days|condition_notes
 * Writes one line per record to stdout, pipe-delimited:
 *   id|days_since_check|is_overdue|risk
 * sorted risk-first (high, medium, low).
 *
 * Contains a real, intentional CWE-121 stack-based buffer overflow (see
 * README "The real bug" section) - condition_notes is copied into a
 * fixed-size stack buffer with strcpy() before a case-insensitive substring
 * search, with no length check. This is not a contrived toy - it is exactly
 * the shape of bug NIST's Juliet Test Suite catalogs under CWE-121 and that
 * NSA/CISA's memory-safe-language guidance (see README) cites by name as a
 * primary reason to move off C/C++ for this class of code.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#define MAX_RECORDS 256
#define NOTES_BUF_SIZE 32   /* the bug: fixed-size, no bound on strcpy below */

typedef struct {
    char id[32];
    int days_since_check;
    int is_overdue;
    char risk[8]; /* "high" | "medium" | "low" */
} RiskResult;

/* THE BUG (CWE-121: Stack-based Buffer Overflow): copies attacker/operator-
 * controlled condition_notes into a fixed 32-byte stack buffer with no
 * length check, then lowercases in place, before searching for "fail".
 * Any condition_notes field of 32+ bytes overflows notes_buf and corrupts
 * adjacent stack memory. See README + verify_parity.py for a live,
 * AddressSanitizer-confirmed trigger of this exact bug on real input. */
static int notes_mention_failure(const char *condition_notes) {
    char notes_buf[NOTES_BUF_SIZE];
    strcpy(notes_buf, condition_notes); /* <-- no bounds check */
    for (int i = 0; notes_buf[i]; i++) {
        notes_buf[i] = (char) tolower((unsigned char) notes_buf[i]);
    }
    return strstr(notes_buf, "fail") != NULL;
}

static void compute_risk(int days_since_check, int check_interval_days,
                          const char *condition_notes, RiskResult *out) {
    out->days_since_check = days_since_check;
    out->is_overdue = days_since_check > check_interval_days;

    double ratio = (double) days_since_check / (double) check_interval_days;
    if (ratio >= 2.0) {
        strcpy(out->risk, "high");
    } else if (ratio >= 1.0) {
        strcpy(out->risk, "medium");
    } else {
        strcpy(out->risk, "low");
    }

    if (notes_mention_failure(condition_notes)) {
        strcpy(out->risk, "high");
    }
}

static int risk_rank(const char *risk) {
    if (strcmp(risk, "high") == 0) return 0;
    if (strcmp(risk, "medium") == 0) return 1;
    return 2;
}

static int compare_by_risk(const void *a, const void *b) {
    return risk_rank(((const RiskResult *) a)->risk) - risk_rank(((const RiskResult *) b)->risk);
}

int main(void) {
    RiskResult results[MAX_RECORDS];
    int count = 0;

    char line[1024];
    while (count < MAX_RECORDS && fgets(line, sizeof(line), stdin)) {
        line[strcspn(line, "\n")] = '\0';
        if (line[0] == '\0') continue;

        char *id = strtok(line, "|");
        char *days_str = strtok(NULL, "|");
        char *interval_str = strtok(NULL, "|");
        char *notes = strtok(NULL, "|");
        if (!id || !days_str || !interval_str) continue;
        if (!notes) notes = "";

        RiskResult *r = &results[count++];
        strncpy(r->id, id, sizeof(r->id) - 1);
        r->id[sizeof(r->id) - 1] = '\0';
        compute_risk(atoi(days_str), atoi(interval_str), notes, r);
    }

    qsort(results, (size_t) count, sizeof(RiskResult), compare_by_risk);

    for (int i = 0; i < count; i++) {
        printf("%s|%d|%d|%s\n", results[i].id, results[i].days_since_check,
               results[i].is_overdue, results[i].risk);
    }

    return 0;
}
