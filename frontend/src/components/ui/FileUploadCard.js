import React, { useState, useRef, forwardRef } from "react";
import { UploadCloud, X, CheckCircle2, Trash2 } from "lucide-react";
import { motion, AnimatePresence } from "framer-motion";

function cn(...classes) {
  return classes.filter(Boolean).join(" ");
}

export const FileUploadCard = forwardRef(function FileUploadCard(
  { className, files = [], onFilesChange, onFileRemove, onClose, onStartScan, isLoading, ...props },
  ref
) {
  const [isDragging, setIsDragging] = useState(false);
  const fileInputRef = useRef(null);

  const handleDragEnter = (e) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(true);
  };

  const handleDragLeave = (e) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(false);
  };

  const handleDragOver = (e) => {
    e.preventDefault();
    e.stopPropagation();
  };

  const handleDrop = (e) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(false);
    const droppedFiles = Array.from(e.dataTransfer.files || []);
    if (droppedFiles.length > 0) {
      onFilesChange(droppedFiles);
    }
  };

  const handleFileSelect = (e) => {
    const selectedFiles = Array.from(e.target.files || []);
    if (selectedFiles.length > 0) {
      onFilesChange(selectedFiles);
    }
  };

  const triggerFileSelect = () => {
    if (fileInputRef.current) {
      fileInputRef.current.click();
    }
  };

  const formatFileSize = (bytes) => {
    if (!bytes || bytes === 0) return "0 KB";
    const k = 1024;
    const sizes = ["Bytes", "KB", "MB", "GB", "TB"];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
  };

  const cardVariants = {
    hidden: { opacity: 0, y: 20 },
    visible: { opacity: 1, y: 0 }
  };

  const fileItemVariants = {
    hidden: { opacity: 0, x: -20 },
    visible: { opacity: 1, x: 0 }
  };

  return (
    <motion.div
      ref={ref}
      variants={cardVariants}
      initial="hidden"
      animate="visible"
      transition={{ duration: 0.3 }}
      className={cn(
        "w-full max-w-xl bg-white rounded-xl border border-gray-200 shadow-sm text-left mx-auto",
        className
      )}
      style={{
        backgroundColor: "#ffffff",
        border: "1px solid #ebebeb",
        borderRadius: "12px",
        padding: "24px",
        maxWidth: "640px",
        width: "100%",
        boxShadow: "0 1px 3px rgba(0,0,0,0.05)"
      }}
      {...props}
    >
      <div>
        <div style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between" }}>
          <div style={{ display: "flex", alignItems: "center", gap: "16px" }}>
            <div style={{
              width: "48px",
              height: "48px",
              borderRadius: "50%",
              backgroundColor: "#f2f2f2",
              display: "flex",
              alignItems: "center",
              justifyContent: "center"
            }}>
              <UploadCloud style={{ width: "24px", height: "24px", color: "#666666" }} />
            </div>
            <div>
              <h3 style={{ fontSize: "18px", fontWeight: "600", color: "#171717", margin: 0 }}>
                Upload PDF Files
              </h3>
              <p style={{ fontSize: "14px", color: "#8f8f8f", marginTop: "2px", margin: 0 }}>
                Select and upload the PDF documents to inspect for malware
              </p>
            </div>
          </div>
          {onClose && (
            <button
              type="button"
              onClick={onClose}
              style={{
                background: "none",
                border: "none",
                cursor: "pointer",
                padding: "4px",
                borderRadius: "50%"
              }}
            >
              <X style={{ width: "16px", height: "16px", color: "#171717" }} />
            </button>
          )}
        </div>

        <div
          onDragEnter={handleDragEnter}
          onDragLeave={handleDragLeave}
          onDragOver={handleDragOver}
          onDrop={handleDrop}
          onClick={triggerFileSelect}
          style={{
            marginTop: "20px",
            border: isDragging ? "2px dashed #171717" : "2px dashed #ebebeb",
            backgroundColor: isDragging ? "rgba(23, 23, 23, 0.04)" : "#fafafa",
            borderRadius: "8px",
            padding: "32px 20px",
            display: "flex",
            flexDirection: "column",
            alignItems: "center",
            justifyContent: "center",
            textAlign: "center",
            cursor: "pointer",
            transition: "all 0.2s ease"
          }}
        >
          <input
            ref={fileInputRef}
            type="file"
            accept=".pdf"
            style={{ display: "none" }}
            onChange={handleFileSelect}
          />
          <UploadCloud style={{ width: "36px", height: "36px", color: "#8f8f8f", marginBottom: "12px" }} />
          <p style={{ fontWeight: "600", color: "#171717", fontSize: "15px", margin: 0 }}>
            Choose a PDF file or drag & drop it here.
          </p>
          <p style={{ fontSize: "12px", color: "#8f8f8f", marginTop: "4px", margin: 0 }}>
            PDF documents with JavaScript tags, auto-launch exploits, or YARA rules.
          </p>
          <button
            type="button"
            style={{
              marginTop: "16px",
              padding: "6px 16px",
              fontSize: "13px",
              fontWeight: "500",
              borderRadius: "6px",
              border: "1px solid #ebebeb",
              backgroundColor: "#ffffff",
              color: "#171717",
              cursor: "pointer",
              pointerEvents: "none"
            }}
          >
            Browse File
          </button>
        </div>
      </div>

      {files.length > 0 && (
        <div style={{ marginTop: "20px", paddingTop: "20px", borderTop: "1px solid #ebebeb" }}>
          <ul style={{ listStyle: "none", padding: 0, margin: 0, display: "flex", flexDirection: "column", gap: "12px" }}>
            <AnimatePresence>
              {files.map((fileItem) => (
                <motion.li
                  key={fileItem.id}
                  variants={fileItemVariants}
                  initial="hidden"
                  animate="visible"
                  exit="hidden"
                  layout
                  style={{
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "space-between",
                    padding: "10px 14px",
                    backgroundColor: "#fafafa",
                    borderRadius: "8px",
                    border: "1px solid #ebebeb"
                  }}
                >
                  <div style={{ display: "flex", alignItems: "center", gap: "12px", flex: 1, minWidth: 0 }}>
                    <div style={{
                      width: "38px",
                      height: "38px",
                      borderRadius: "6px",
                      backgroundColor: "#ebebeb",
                      display: "flex",
                      alignItems: "center",
                      justifyContent: "center",
                      fontSize: "11px",
                      fontWeight: "700",
                      color: "#4d4d4d",
                      flexShrink: 0
                    }}>
                      PDF
                    </div>
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <p style={{
                        fontSize: "14px",
                        fontWeight: "500",
                        color: "#171717",
                        margin: 0,
                        whiteSpace: "nowrap",
                        overflow: "hidden",
                        textOverflow: "ellipsis"
                      }}>
                        {fileItem.file.name}
                      </p>
                      <div style={{ fontSize: "12px", color: "#8f8f8f", marginTop: "2px" }}>
                        <span>{formatFileSize(fileItem.file.size)}</span>
                        <span style={{ margin: "0 6px" }}>•</span>
                        <span style={{
                          color: fileItem.status === 'completed' ? '#10b981' : '#0070f3',
                          fontWeight: "500"
                        }}>
                          {fileItem.status === 'completed' ? 'Ready to analyze' : 'Uploading...'}
                        </span>
                      </div>
                    </div>
                  </div>

                  <div style={{ display: "flex", alignItems: "center", gap: "8px", flexShrink: 0 }}>
                    {fileItem.status === 'completed' && (
                      <CheckCircle2 style={{ width: "18px", height: "18px", color: "#10b981" }} />
                    )}
                    <button
                      type="button"
                      onClick={() => onFileRemove(fileItem.id)}
                      style={{
                        background: "none",
                        border: "none",
                        cursor: "pointer",
                        padding: "6px",
                        borderRadius: "50%",
                        color: "#8f8f8f"
                      }}
                    >
                      {fileItem.status === 'completed' ? (
                        <Trash2 style={{ width: "16px", height: "16px" }} />
                      ) : (
                        <X style={{ width: "16px", height: "16px" }} />
                      )}
                    </button>
                  </div>
                </motion.li>
              ))}
            </AnimatePresence>
          </ul>

          {/* Scan Action Button */}
          <div style={{ marginTop: "16px", textAlign: "right" }}>
            <button
              type="button"
              onClick={onStartScan}
              disabled={isLoading}
              style={{
                backgroundColor: "#171717",
                color: "#ffffff",
                borderRadius: "100px",
                padding: "10px 24px",
                fontSize: "14px",
                fontWeight: "500",
                border: "none",
                cursor: "pointer",
                opacity: isLoading ? 0.6 : 1
              }}
            >
              {isLoading ? "Running Security Scan..." : "Analyze Document"}
            </button>
          </div>
        </div>
      )}
    </motion.div>
  );
});
