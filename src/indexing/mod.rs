//! Indexing schema and index type definitions.
//!
//! Pure data types for describing subgrove schemas, property definitions,
//! and index configurations. These are shared between the storage and
//! indexing subsystems so that `storage` can reference them without
//! depending on the `indexing` module.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;

// ---------------------------------------------------------------------------
// Schema types
// ---------------------------------------------------------------------------

/// Schema definition for a subgrove (indexed data collection).
///
/// Defines the structure, validation rules, and indexes for stored documents.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubgroveSchema {
    /// Unique name for this schema/collection.
    pub name: String,
    /// Schema version string.
    #[serde(default)]
    pub version: String,

    /// Whether documents can be updated after creation.
    #[serde(default = "default_true")]
    pub documents_mutable: bool,
    /// Whether documents can be deleted.
    #[serde(default = "default_true")]
    pub can_be_deleted: bool,
    /// Transferability setting (Dash-compatible).
    #[serde(default)]
    pub transferable: Option<u8>,
    /// Trade mode setting (Dash-compatible).
    #[serde(default)]
    pub trade_mode: Option<u8>,

    /// JSON Schema-style type definition.
    pub schema: SchemaDefinition,

    /// Index definitions for efficient querying.
    #[serde(default)]
    pub indices: Vec<IndexDefinition>,

    /// Enabled feature flags.
    #[serde(default)]
    pub features: Vec<String>,
}

fn default_true() -> bool {
    true
}

/// JSON Schema-style type definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchemaDefinition {
    /// Type of the schema ("object", "array", etc.).
    #[serde(rename = "type")]
    pub schema_type: String,
    /// Property definitions for object types.
    #[serde(default)]
    pub properties: HashMap<String, PropertyDefinition>,
    /// List of required property names.
    #[serde(default)]
    pub required: Vec<String>,
    /// Whether additional properties beyond defined ones are allowed.
    #[serde(default)]
    pub additional_properties: bool,
}

/// Definition of a property/field in a schema.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PropertyDefinition {
    /// Data type of this property.
    #[serde(rename = "type")]
    pub property_type: PropertyType,

    /// Human-readable description.
    #[serde(default)]
    pub description: Option<String>,

    /// Regex pattern for string validation.
    #[serde(default)]
    pub pattern: Option<String>,
    /// Minimum string length.
    #[serde(default)]
    pub min_length: Option<u32>,
    /// Maximum string length.
    #[serde(default)]
    pub max_length: Option<u32>,
    /// Minimum numeric value.
    #[serde(default)]
    pub minimum: Option<f64>,
    /// Maximum numeric value.
    #[serde(default)]
    pub maximum: Option<f64>,
    /// Allowed values (enumeration).
    #[serde(default)]
    pub enum_values: Option<Vec<Value>>,

    /// Inline index hint for this property.
    #[serde(default)]
    pub index: Option<InlineIndexType>,

    /// Item type definition for arrays.
    #[serde(default)]
    pub items: Option<Box<PropertyDefinition>>,
    /// Minimum array length.
    #[serde(default)]
    pub min_items: Option<u32>,
    /// Maximum array length.
    #[serde(default)]
    pub max_items: Option<u32>,

    /// Nested properties for object types.
    #[serde(default)]
    pub properties: Option<HashMap<String, PropertyDefinition>>,

    /// Whether this field cannot be changed after creation.
    #[serde(default)]
    pub immutable: bool,
    /// Whether this field must be unique across all documents.
    #[serde(default)]
    pub unique: bool,
}

impl Default for PropertyDefinition {
    fn default() -> Self {
        Self {
            property_type: PropertyType::String,
            description: None,
            pattern: None,
            min_length: None,
            max_length: None,
            minimum: None,
            maximum: None,
            enum_values: None,
            index: None,
            items: None,
            min_items: None,
            max_items: None,
            properties: None,
            immutable: false,
            unique: false,
        }
    }
}

/// Supported property data types.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PropertyType {
    /// UTF-8 string.
    String,
    /// Floating-point number.
    Number,
    /// Integer number.
    Integer,
    /// Boolean true/false.
    Boolean,
    /// Array of items.
    Array,
    /// Nested object.
    Object,
    /// Null value.
    #[serde(rename = "null")]
    Null,
}

/// Index types that can be specified inline on a property.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum InlineIndexType {
    /// Unique index (one-to-one mapping).
    Unique,
    /// Hash index for equality lookups.
    Hash,
    /// Range index for ordered queries.
    Range,
    /// Inverted index for array contains queries.
    Inverted,
    /// Prefix index for autocomplete.
    Prefix,
}

impl std::fmt::Display for InlineIndexType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InlineIndexType::Unique => write!(f, "unique"),
            InlineIndexType::Hash => write!(f, "hash"),
            InlineIndexType::Range => write!(f, "range"),
            InlineIndexType::Inverted => write!(f, "inverted"),
            InlineIndexType::Prefix => write!(f, "prefix"),
        }
    }
}

// ---------------------------------------------------------------------------
// Index types
// ---------------------------------------------------------------------------

/// Types of indexes supported by the Willow indexing system.
///
/// Each index type provides different query capabilities and performance characteristics.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum IndexType {
    /// Unique index enforcing one-to-one mapping (optimal for primary keys).
    #[serde(rename = "unique")]
    Unique {
        /// The field to index.
        field: String,
        /// If true, null values are not indexed (allowing multiple nulls).
        #[serde(default)]
        sparse: bool,
    },

    /// Hash index for fast equality lookups.
    #[serde(rename = "hash")]
    Hash {
        /// The field to index.
        field: String,
        /// If true, null values are not indexed.
        #[serde(default)]
        sparse: bool,
    },

    /// Range index for ordered queries and sorting.
    #[serde(rename = "range")]
    Range {
        /// The field to index.
        field: String,
        /// If true, null values are not indexed.
        #[serde(default)]
        sparse: bool,
    },

    /// Compound index on multiple fields.
    #[serde(rename = "compound")]
    Compound {
        /// Fields to include in the compound index with sort order.
        fields: Vec<IndexField>,
        /// If true, the combination of fields must be unique.
        #[serde(default)]
        unique: bool,
    },

    /// Inverted index for array fields.
    #[serde(rename = "inverted")]
    Inverted {
        /// The array field to index.
        field: String,
        /// Maximum number of array values to index per document.
        #[serde(default)]
        max_values: Option<u32>,
    },

    /// Prefix index for autocomplete and prefix matching.
    #[serde(rename = "prefix")]
    Prefix {
        /// The string field to index.
        field: String,
        /// Delimiter for splitting the field into parts.
        #[serde(default)]
        delimiter: String,
    },
}

impl IndexType {
    /// Returns the string name of this index type.
    pub fn name(&self) -> &'static str {
        match self {
            IndexType::Unique { .. } => "unique",
            IndexType::Hash { .. } => "hash",
            IndexType::Range { .. } => "range",
            IndexType::Compound { .. } => "compound",
            IndexType::Inverted { .. } => "inverted",
            IndexType::Prefix { .. } => "prefix",
        }
    }
}

/// A field specification for compound indexes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexField {
    /// Name of the field to include.
    pub name: String,
    /// Sort order for this field in the index.
    pub order: SortOrder,
}

/// Sort order for index fields.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SortOrder {
    /// Ascending order (smallest to largest).
    Asc,
    /// Descending order (largest to smallest).
    Desc,
}

/// Definition of an index on a subgrove.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexDefinition {
    /// Unique name for this index.
    pub name: String,
    /// The type and configuration of the index.
    #[serde(flatten)]
    pub index_type: IndexType,
    /// Configuration for contested resources (e.g., usernames).
    #[serde(default)]
    pub contested: Option<ContestedConfig>,
    /// Whether null values should be searchable.
    #[serde(default)]
    pub null_searchable: bool,
}

/// Configuration for contested (rate-limited) resources.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContestedConfig {
    /// Field patterns that trigger contested handling.
    pub field_matches: Vec<FieldMatch>,
    /// Resolution strategy identifier.
    pub resolution: u8,
    /// Human-readable description of the contested resource.
    pub description: String,
}

/// Pattern matching configuration for field values.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldMatch {
    /// Name of the field to match.
    pub field: String,
    /// Regex pattern the field value must match.
    pub regex_pattern: String,
}
